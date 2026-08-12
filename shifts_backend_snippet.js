/*
  SHIFT SCHEDULING — additions for index.js
  =================================================================
  1. Add `const crypto = require('crypto');` near your other require()
     calls at the top of the file.
  2. Add ensureShiftsTable() near the other ensure* functions and call it
     once at startup, same pattern as ensureGuardCertificationsTable().
  3. Add the helper functions (computeShiftDurationHours, generateShiftDates,
     TIME_FORMAT_REGEX) anywhere above the endpoints that use them.
  4. Add the 5 endpoints below anywhere after requireAuth/requireAdmin are
     defined — grouping them near guard-assignments keeps things tidy.
*/

const TIME_FORMAT_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;
const MAX_WEEKLY_REPEAT_DAYS = 182;   // ~26 weeks
const MAX_MONTHLY_REPEAT_DAYS = 366;  // ~12 months
const MAX_GENERATED_SHIFTS = 250;     // hard safety cap regardless of range

async function ensureShiftsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shifts (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      shift_date DATE NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      employment_type TEXT NOT NULL DEFAULT 'full_time',
      recurrence_group_id TEXT,
      notes TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_guard_lookup ON shifts (tenant_id, user_id, shift_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_site_lookup ON shifts (tenant_id, site_id, shift_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_series ON shifts (tenant_id, recurrence_group_id)`);
  console.log('Shifts table ready');
}
ensureShiftsTable();

// Handles overnight shifts (e.g. 22:00 -> 06:00) by adding 24h when the
// end time is not after the start time.
function computeShiftDurationHours(startTime, endTime) {
  const [sh, sm] = startTime.split(':').map(Number);
  const [eh, em] = endTime.split(':').map(Number);
  let diffMinutes = (eh * 60 + em) - (sh * 60 + sm);
  if (diffMinutes <= 0) diffMinutes += 24 * 60;
  return Math.round((diffMinutes / 60) * 100) / 100;
}

// Expands a shift request into concrete calendar dates. `recurrence` is
// 'none' | 'weekly' | 'monthly'. For weekly, `days_of_week` is an array of
// 0(Sun)-6(Sat) matching Luxon's .weekday convention adjusted below. For
// monthly, occurrences fall on the same day-of-month as start_date,
// clamped to the last day of shorter months (e.g. 31st -> 28th in Feb).
function generateShiftDates({ recurrence, start_date, repeat_until, days_of_week }) {
  const startDt = DateTime.fromISO(start_date).startOf('day');
  if (!startDt.isValid) throw Object.assign(new Error('start_date is invalid'), { statusCode: 400 });

  if (recurrence === 'none') {
    return [startDt];
  }

  if (!repeat_until) {
    throw Object.assign(new Error('repeat_until is required for recurring shifts'), { statusCode: 400 });
  }
  const untilDt = DateTime.fromISO(repeat_until).startOf('day');
  if (!untilDt.isValid || untilDt < startDt) {
    throw Object.assign(new Error('repeat_until must be a valid date on or after start_date'), { statusCode: 400 });
  }

  const totalDays = untilDt.diff(startDt, 'days').days;

  if (recurrence === 'weekly') {
    if (totalDays > MAX_WEEKLY_REPEAT_DAYS) {
      throw Object.assign(new Error(`Weekly recurrence cannot span more than ${MAX_WEEKLY_REPEAT_DAYS} days`), { statusCode: 400 });
    }
    if (!Array.isArray(days_of_week) || days_of_week.length === 0) {
      throw Object.assign(new Error('days_of_week is required for weekly recurrence (e.g. [1,2,3,4,5])'), { statusCode: 400 });
    }
    // Luxon weekday: 1=Mon...7=Sun. Frontend sends 0=Sun...6=Sat (JS Date
    // convention) since that's more familiar — convert here.
    const luxonWeekdays = new Set(days_of_week.map(d => (Number(d) === 0 ? 7 : Number(d))));
    const dates = [];
    let cursor = startDt;
    while (cursor <= untilDt && dates.length < MAX_GENERATED_SHIFTS) {
      if (luxonWeekdays.has(cursor.weekday)) dates.push(cursor);
      cursor = cursor.plus({ days: 1 });
    }
    return dates;
  }

  if (recurrence === 'monthly') {
    if (totalDays > MAX_MONTHLY_REPEAT_DAYS) {
      throw Object.assign(new Error(`Monthly recurrence cannot span more than ${MAX_MONTHLY_REPEAT_DAYS} days`), { statusCode: 400 });
    }
    const dayOfMonth = startDt.day;
    const dates = [];
    let cursor = startDt;
    while (cursor <= untilDt && dates.length < MAX_GENERATED_SHIFTS) {
      const daysInMonth = cursor.daysInMonth;
      const clampedDay = Math.min(dayOfMonth, daysInMonth);
      const occurrence = cursor.set({ day: clampedDay });
      if (occurrence >= startDt && occurrence <= untilDt) dates.push(occurrence);
      cursor = cursor.plus({ months: 1 }).startOf('month');
    }
    return dates;
  }

  throw Object.assign(new Error('recurrence must be none, weekly, or monthly'), { statusCode: 400 });
}

app.post('/api/shifts', requireAuth, requireAdmin, async (req, res) => {
  const {
    tenant_id, site_id, user_id, start_date, start_time, end_time,
    employment_type, recurrence, days_of_week, repeat_until, notes
  } = req.body;

  if (!tenant_id || !site_id || !user_id || !start_date || !start_time || !end_time) {
    return res.status(400).json({ error: 'tenant_id, site_id, user_id, start_date, start_time, and end_time are required' });
  }
  if (!TIME_FORMAT_REGEX.test(start_time) || !TIME_FORMAT_REGEX.test(end_time)) {
    return res.status(400).json({ error: 'start_time and end_time must be in HH:MM 24-hour format' });
  }
  const empType = ['full_time', 'part_time'].includes(employment_type) ? employment_type : 'full_time';
  const recurrenceType = ['none', 'weekly', 'monthly'].includes(recurrence) ? recurrence : 'none';

  try {
    const dates = generateShiftDates({ recurrence: recurrenceType, start_date, repeat_until, days_of_week });
    if (dates.length === 0) {
      return res.status(400).json({ error: 'No shift dates were generated — check your recurrence settings (e.g. selected days of week).' });
    }

    const result = await withTenant(tenant_id, async (client) => {
      const guardCheck = await client.query(
        "SELECT id FROM users WHERE id = $1 AND tenant_id = $2 AND role = 'guard'",
        [user_id, tenant_id]
      );
      if (guardCheck.rows.length === 0) {
        const err = new Error('Guard not found for this tenant');
        err.statusCode = 404;
        throw err;
      }
      const siteCheck = await client.query('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [site_id, tenant_id]);
      if (siteCheck.rows.length === 0) {
        const err = new Error('Site not found for this tenant');
        err.statusCode = 404;
        throw err;
      }

      const seriesId = recurrenceType !== 'none' ? crypto.randomUUID() : null;
      const inserted = [];
      for (const dt of dates) {
        const insertRes = await client.query(
          `INSERT INTO shifts (tenant_id, site_id, user_id, shift_date, start_time, end_time, employment_type, recurrence_group_id, notes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
          [tenant_id, site_id, user_id, dt.toISODate(), start_time, end_time, empType, seriesId, notes || null]
        );
        inserted.push(insertRes.rows[0]);
      }
      return inserted;
    });

    res.status(201).json({ created_count: result.length, recurrence_group_id: result[0].recurrence_group_id, shifts: result });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/shifts', requireAuth, async (req, res) => {
  const { tenant_id, site_id, user_id, start_date, end_date } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });

  // Guards can only ever see their own shifts, regardless of what user_id
  // they pass — same enforcement pattern used for guard-assignments.
  const effectiveUserId = req.auth.role === 'admin' ? user_id : req.auth.user_id;
  if (req.auth.role !== 'admin' && user_id && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own shifts' });
  }

  try {
    const result = await withTenant(tenant_id, (client) => {
      let query = `SELECT sh.*, u.email as guard_email, s.name as site_name
                   FROM shifts sh
                   JOIN users u ON u.id = sh.user_id
                   JOIN sites s ON s.id = sh.site_id
                   WHERE sh.tenant_id = $1`;
      const params = [tenant_id];

      if (effectiveUserId) { params.push(effectiveUserId); query += ` AND sh.user_id = $${params.length}`; }
      if (site_id) { params.push(site_id); query += ` AND sh.site_id = $${params.length}`; }
      if (start_date) { params.push(start_date); query += ` AND sh.shift_date >= $${params.length}`; }
      if (end_date) { params.push(end_date); query += ` AND sh.shift_date <= $${params.length}`; }
      if (!start_date && !end_date) { query += ` AND sh.shift_date >= CURRENT_DATE`; }

      query += ' ORDER BY sh.shift_date ASC, sh.start_time ASC LIMIT 500';
      return client.query(query, params);
    });

    const withDuration = result.rows.map(s => ({ ...s, duration_hours: computeShiftDurationHours(s.start_time, s.end_time) }));
    res.json(withDuration);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, site_id, shift_date, start_time, end_time, employment_type, notes } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });

  if (start_time && !TIME_FORMAT_REGEX.test(start_time)) {
    return res.status(400).json({ error: 'start_time must be in HH:MM 24-hour format' });
  }
  if (end_time && !TIME_FORMAT_REGEX.test(end_time)) {
    return res.status(400).json({ error: 'end_time must be in HH:MM 24-hour format' });
  }
  const empType = employment_type && ['full_time', 'part_time'].includes(employment_type) ? employment_type : null;

  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `UPDATE shifts
         SET site_id = COALESCE($1, site_id),
             shift_date = COALESCE($2, shift_date),
             start_time = COALESCE($3, start_time),
             end_time = COALESCE($4, end_time),
             employment_type = COALESCE($5, employment_type),
             notes = $6
         WHERE id = $7 AND tenant_id = $8 RETURNING *`,
        [site_id || null, shift_date || null, start_time || null, end_time || null, empType, notes ?? null, id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query('DELETE FROM shifts WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deletes every future occurrence in a recurring series (shift_date >=
// today) — past occurrences are preserved so historical records/reports
// stay intact even after a recurring shift is cancelled going forward.
app.delete('/api/shifts/series/:recurrenceGroupId', requireAuth, requireAdmin, async (req, res) => {
  const { recurrenceGroupId } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `DELETE FROM shifts WHERE tenant_id = $1 AND recurrence_group_id = $2 AND shift_date >= CURRENT_DATE RETURNING id`,
        [tenant_id, recurrenceGroupId]
      )
    );
    res.json({ deleted_count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
