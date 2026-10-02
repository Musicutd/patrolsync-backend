# V01 Vision contract sketches

These are review-only interface sketches. No ingest or persistence endpoint exists in V01. Later stages must validate every field, authenticate the Edge Agent, enforce tenant/site binding and use versioned schemas.

| Contract | Minimum fields | Boundary |
|---|---|---|
| Edge identity | opaque `edge_id`, `tenant_id`, `site_id`, `version`, `status` | Enrolment and credentials are not part of browser payloads. |
| Camera reference | opaque `camera_id`, `edge_id`, `site_id`, `entrance_id`, `mode` | RTSP/ONVIF URL and password remain local to the Edge Agent. |
| Anonymous count event | `event_id`, `camera_id`, `line_id`, `direction` (`IN`/`OUT`), `occurred_at`, `confidence` | No image, face, person identifier or persistent tracking ID. |
| Heartbeat | `edge_id`, `observed_at`, `agent_version`, health state and bounded resource summaries | No local network URL or secret. |
| Confidence state | `site_id`, `mode` (`FOOTFALL_ONLY`/`FULL_OCCUPANCY`), `state` (`RELIABLE`/`DEGRADED`/`UNKNOWN`), `reason`, `as_of` | Never present degraded occupancy as a fully reliable fact. |

Cloud event ingestion, occupancy calculation, retention and camera configuration require their later dedicated stages and migrations. These sketches do not authorize collection or processing of CCTV footage.
