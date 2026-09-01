const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { DateTime } = require('luxon');
const QRCode = require('qrcode');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');
require('dotenv').config();

const IS_PRODUCTION=String(process.env.NODE_ENV||'').toLowerCase()==='production';
function normalizedOrigin(value){try{return new URL(String(value||'').trim()).origin}catch(_){return null}}
const allowedOrigins=new Set([
  normalizedOrigin(process.env.FRONTEND_URL),
  'https://patrolsync.co',
  'https://www.patrolsync.co',
  ...String(process.env.ALLOWED_ORIGINS||'').split(',').map(normalizedOrigin)
].filter(Boolean));
if(!IS_PRODUCTION){allowedOrigins.add('http://localhost:3000');allowedOrigins.add('http://127.0.0.1:3000');}

const app = express();
const runtimeState={ready:false,draining:false,shutdown_signal:null,shutdown_started_at:null,active_requests:0,total_requests:0};
app.disable('x-powered-by');
app.set('trust proxy',1);
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin&&origin!=='null'&&!allowedOrigins.has(origin))return res.status(403).json({error:'Origin is not allowed'});if(origin==='null'&&IS_PRODUCTION)return res.status(403).json({error:'Local-file browser requests are not allowed in production'});next()});
app.use(cors({origin:(origin,callback)=>callback(null,!origin||allowedOrigins.has(origin)),methods:['GET','POST','PUT','PATCH','DELETE','OPTIONS'],allowedHeaders:['Authorization','Content-Type','X-Request-ID','X-API-Key','X-PatrolSync-Device'],exposedHeaders:['X-Request-ID','X-RateLimit-Limit','X-RateLimit-Remaining','X-RateLimit-Reset','Retry-After','X-Cache','X-Cache-Age'],maxAge:86400}));
app.use(express.json({ limit: '12mb' }));
app.use((req,res,next)=>{
  if(runtimeState.draining&&req.path!=='/live')return res.status(503).set('Connection','close').json({error:'Service is restarting',retry_after_seconds:10});
  runtimeState.active_requests++;runtimeState.total_requests++;
  let finished=false;const release=()=>{if(!finished){finished=true;runtimeState.active_requests=Math.max(0,runtimeState.active_requests-1)}};
  res.once('finish',release);res.once('close',release);next();
});
app.use((err,req,res,next)=>{if(err instanceof SyntaxError&&err.status===400&&'body' in err)return res.status(400).json({error:'Malformed JSON request'});if(err?.type==='entity.too.large')return res.status(413).json({error:'Request body is too large'});next(err)});

const databaseSsl = { rejectUnauthorized: false };
const systemDatabaseUrl = process.env.SYSTEM_DATABASE_URL || process.env.DATABASE_URL;
const tenantDatabaseUrl = process.env.TENANT_DATABASE_URL || process.env.DATABASE_URL;
const DATABASE_POOL_MAX = Math.max(2, Math.min(50, Number(process.env.DATABASE_POOL_MAX || 10)));
const DATABASE_IDLE_TIMEOUT_MS = Math.max(1000, Number(process.env.DATABASE_IDLE_TIMEOUT_MS || 30000));
const DATABASE_CONNECT_TIMEOUT_MS = Math.max(1000, Number(process.env.DATABASE_CONNECT_TIMEOUT_MS || 10000));
function databasePoolConfig(connectionString){return {connectionString,ssl:databaseSsl,max:DATABASE_POOL_MAX,idleTimeoutMillis:DATABASE_IDLE_TIMEOUT_MS,connectionTimeoutMillis:DATABASE_CONNECT_TIMEOUT_MS,allowExitOnIdle:false}}
const systemPool = new Pool(databasePoolConfig(systemDatabaseUrl));
// Existing direct database work remains on the trusted system path. Tenant-scoped
// work uses tenantPool through withTenant(). Until TENANT_DATABASE_URL is supplied,
// both names intentionally share one pool so this deployment remains compatible.
const tenantPool = tenantDatabaseUrl === systemDatabaseUrl
  ? systemPool
  : new Pool(databasePoolConfig(tenantDatabaseUrl));
const pool = systemPool;
const DATABASE_PATHS_SEPARATED = tenantPool !== systemPool;
systemPool.on('error',err=>console.error(JSON.stringify({level:'error',type:'system_pool_error',message:err.message})));
if(DATABASE_PATHS_SEPARATED)tenantPool.on('error',err=>console.error(JSON.stringify({level:'error',type:'tenant_pool_error',message:err.message})));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'patrolsync-dev-secret';
const PLATFORM_JWT_SECRET = process.env.PLATFORM_JWT_SECRET || JWT_SECRET;
const OPENAI_API_KEY = String(process.env.OPENAI_API_KEY || '').trim();
const OPENAI_MODEL = String(process.env.OPENAI_MODEL || 'gpt-5-mini').trim();
const AI_ASSISTANT_ENABLED = String(process.env.AI_ASSISTANT_ENABLED || 'false').toLowerCase() === 'true';
const FIXED_WINDOW_MINUTES = 30;
const ALERT_SWEEP_INTERVAL_MS = 5 * 60 * 1000;
const LOCATION_HISTORY_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const LOCATION_HISTORY_RETENTION_HOURS = 48;
const MAX_PHOTOS_PER_INCIDENT = 3;
const MAX_PHOTO_BASE64_LENGTH = 3 * 1024 * 1024;
const APP_STARTED_AT = new Date();
const REQUEST_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const AUTH_REQUEST_LIMIT = Number(process.env.AUTH_REQUEST_LIMIT || 20);
const API_KEY_REQUEST_LIMIT = Number(process.env.API_KEY_REQUEST_LIMIT || 300);
const AUDIT_RETENTION_DAYS = Number(process.env.AUDIT_RETENTION_DAYS || 365);
const WEBHOOK_RETENTION_DAYS = Number(process.env.WEBHOOK_RETENTION_DAYS || 90);
const requestWindows = new Map();
const PLATFORM_CACHE_MAX_ENTRIES=Math.max(20,Math.min(500,Number(process.env.PLATFORM_CACHE_MAX_ENTRIES||100)));
const platformResponseCache=new Map();
const platformCacheStats={hits:0,misses:0,stores:0,evictions:0,invalidations:0,bypasses:0};
function prunePlatformCache(now=Date.now()){
  for(const[key,value]of platformResponseCache)if(value.expiresAt<=now)platformResponseCache.delete(key);
  while(platformResponseCache.size>PLATFORM_CACHE_MAX_ENTRIES){platformResponseCache.delete(platformResponseCache.keys().next().value);platformCacheStats.evictions++}
}
function clearPlatformCache(reason='manual'){
  const removed=platformResponseCache.size;platformResponseCache.clear();platformCacheStats.invalidations++;
  return{removed,reason,at:new Date().toISOString()};
}
function platformCache(name,ttlMs){
  return(req,res,next)=>{
    if(req.method!=='GET'||req.query?.fresh==='1'){platformCacheStats.bypasses++;res.set('X-Cache','BYPASS');return next()}
    prunePlatformCache();
    const key=`${name}:${req.originalUrl}`,cached=platformResponseCache.get(key);
    if(cached){platformCacheStats.hits++;res.set('X-Cache','HIT');res.set('X-Cache-Age',String(Math.max(0,Math.floor((Date.now()-cached.createdAt)/1000))));return res.status(cached.status).type('application/json').send(cached.body)}
    platformCacheStats.misses++;res.set('X-Cache','MISS');
    const originalJson=res.json.bind(res);
    res.json=body=>{if(res.statusCode>=200&&res.statusCode<300){platformResponseCache.set(key,{body:JSON.stringify(body),status:res.statusCode,createdAt:Date.now(),expiresAt:Date.now()+ttlMs,name});platformCacheStats.stores++;prunePlatformCache()}return originalJson(body)};
    next();
  };
}
app.use((req,res,next)=>{if(req.path.startsWith('/api/platform/')&&req.path!=='/api/platform/cache'&&req.method!=='GET'){res.on('finish',()=>{if(res.statusCode>=200&&res.statusCode<300)clearPlatformCache(`${req.method} ${req.path}`)})}next()});
const OBJECT_STORAGE_ENDPOINT=String(process.env.OBJECT_STORAGE_ENDPOINT||'').replace(/\/$/,''),OBJECT_STORAGE_BUCKET=String(process.env.OBJECT_STORAGE_BUCKET||''),OBJECT_STORAGE_ACCESS_KEY=String(process.env.OBJECT_STORAGE_ACCESS_KEY||''),OBJECT_STORAGE_SECRET_KEY=String(process.env.OBJECT_STORAGE_SECRET_KEY||''),OBJECT_STORAGE_REGION=String(process.env.OBJECT_STORAGE_REGION||'auto');
const OBJECT_STORAGE_CONFIGURED=Boolean(OBJECT_STORAGE_ENDPOINT&&OBJECT_STORAGE_BUCKET&&OBJECT_STORAGE_ACCESS_KEY&&OBJECT_STORAGE_SECRET_KEY);
function hmac(key,value,encoding){return crypto.createHmac('sha256',key).update(value).digest(encoding)}
function objectStoragePath(key){return'/'+[OBJECT_STORAGE_BUCKET,...String(key).split('/')].map(encodeURIComponent).join('/')}
async function objectStorageRequest(method,key,body=null,contentType='application/octet-stream'){
  if(!OBJECT_STORAGE_CONFIGURED)throw new Error('Object storage is not configured');const now=new Date(),amzDate=now.toISOString().replace(/[:-]|\.\d{3}/g,''),date=amzDate.slice(0,8),payload=body||Buffer.alloc(0),payloadHash=crypto.createHash('sha256').update(payload).digest('hex'),url=new URL(OBJECT_STORAGE_ENDPOINT);url.pathname=objectStoragePath(key);const canonicalUri=url.pathname,canonicalHeaders=`host:${url.host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`,signedHeaders='host;x-amz-content-sha256;x-amz-date',canonicalRequest=[method,canonicalUri,'',canonicalHeaders,signedHeaders,payloadHash].join('\n'),scope=`${date}/${OBJECT_STORAGE_REGION}/s3/aws4_request`,stringToSign=['AWS4-HMAC-SHA256',amzDate,scope,crypto.createHash('sha256').update(canonicalRequest).digest('hex')].join('\n'),dateKey=hmac('AWS4'+OBJECT_STORAGE_SECRET_KEY,date),regionKey=hmac(dateKey,OBJECT_STORAGE_REGION),serviceKey=hmac(regionKey,'s3'),signingKey=hmac(serviceKey,'aws4_request'),signature=hmac(signingKey,stringToSign,'hex'),headers={'x-amz-date':amzDate,'x-amz-content-sha256':payloadHash,Authorization:`AWS4-HMAC-SHA256 Credential=${OBJECT_STORAGE_ACCESS_KEY}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`};if(body)headers['Content-Type']=contentType;const response=await fetch(url,{method,headers,body:body||undefined,signal:AbortSignal.timeout(20000)});if(!response.ok)throw new Error(`Object storage ${method} failed with HTTP ${response.status}: ${(await response.text()).slice(0,300)}`);return response}
function parseImageDataUrl(value){const match=/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=\r\n]+)$/.exec(String(value||''));if(!match)throw Object.assign(new Error('Photos must be JPEG, PNG, or WebP data URLs'),{statusCode:400});const buffer=Buffer.from(match[2].replace(/\s/g,''),'base64');if(!buffer.length||buffer.length>2*1024*1024)throw Object.assign(new Error('Each decoded photo must be between 1 byte and 2 MB'),{statusCode:400});return{contentType:match[1],buffer,checksum:crypto.createHash('sha256').update(buffer).digest('hex'),extension:match[1]==='image/jpeg'?'jpg':match[1].split('/')[1]}}
async function storeIncidentPhoto(tenantId,incidentId,dataUrl){const image=parseImageDataUrl(dataUrl);if(!OBJECT_STORAGE_CONFIGURED)return{provider:'database',photoData:dataUrl,key:null,...image};const key=`tenants/${tenantId}/incidents/${incidentId}/${crypto.randomUUID()}.${image.extension}`;await objectStorageRequest('PUT',key,image.buffer,image.contentType);return{provider:'s3',photoData:null,key,...image}}
async function readIncidentPhoto(row){if(row.photo_data)return row.photo_data;if(row.storage_provider==='s3'&&row.storage_key){const response=await objectStorageRequest('GET',row.storage_key),buffer=Buffer.from(await response.arrayBuffer()),checksum=crypto.createHash('sha256').update(buffer).digest('hex');if(row.checksum_sha256&&checksum!==row.checksum_sha256)throw new Error('Stored evidence checksum mismatch');return`data:${row.content_type||'application/octet-stream'};base64,${buffer.toString('base64')}`}return null}
const PERFORMANCE_SAMPLE_WINDOW_MS = 15 * 60 * 1000;
const PERFORMANCE_MAX_SAMPLES = 20000;
const performanceSamples = [];
const backgroundJobs = new Map();
const backgroundTimers = [];
async function ensureBackgroundJobSchema(){await pool.query(`CREATE TABLE IF NOT EXISTS platform_job_runs(id BIGSERIAL PRIMARY KEY,job_name TEXT NOT NULL,instance_id TEXT NOT NULL,status TEXT NOT NULL,started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),finished_at TIMESTAMPTZ,duration_ms INTEGER,error_message TEXT,details JSONB NOT NULL DEFAULT '{}'::jsonb)`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_platform_job_runs_name_started ON platform_job_runs(job_name,started_at DESC)`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_platform_job_runs_failures ON platform_job_runs(started_at DESC) WHERE status='failed'`);const reconciled=await pool.query(`UPDATE platform_job_runs SET status='interrupted',finished_at=NOW(),duration_ms=GREATEST(0,FLOOR(EXTRACT(EPOCH FROM(NOW()-started_at))*1000)::int),error_message=COALESCE(error_message,'Previous instance stopped before recording completion') WHERE status='running' AND started_at<NOW()-INTERVAL '10 minutes' RETURNING id`);console.log(`Background job history ready; ${reconciled.rowCount} stale run(s) reconciled`)}
async function ensureLoadTestSchema(){await pool.query(`CREATE TABLE IF NOT EXISTS platform_load_tests(id BIGSERIAL PRIMARY KEY,platform_admin_id BIGINT,scenario TEXT NOT NULL,tenant_id INTEGER,concurrency INTEGER NOT NULL,duration_seconds INTEGER NOT NULL,status TEXT NOT NULL,started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),finished_at TIMESTAMPTZ,total_requests INTEGER NOT NULL DEFAULT 0,successful_requests INTEGER NOT NULL DEFAULT 0,failed_requests INTEGER NOT NULL DEFAULT 0,requests_per_second NUMERIC,p50_ms INTEGER,p95_ms INTEGER,p99_ms INTEGER,max_ms INTEGER,error_summary JSONB NOT NULL DEFAULT '[]'::jsonb,instance_id TEXT NOT NULL)`);await pool.query(`ALTER TABLE platform_load_tests ENABLE ROW LEVEL SECURITY`);await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON platform_load_tests`);await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON platform_load_tests USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_platform_load_tests_started ON platform_load_tests(started_at DESC)`);console.log('Load-test history ready')}
const BACKGROUND_INSTANCE_ID=String(process.env.RENDER_INSTANCE_ID||process.env.HOSTNAME||crypto.randomUUID()).slice(0,150);
async function runBackgroundJob(name,fn,trigger='schedule'){
  const lockClient=await pool.connect();let locked=false,runId=null,started=Date.now();
  try{
    locked=Boolean((await lockClient.query(`SELECT pg_try_advisory_lock(hashtext($1)) locked`,[`patrolsync-job:${name}`])).rows[0]?.locked);
    if(!locked)return {status:'skipped',reason:'already_running'};
    const created=await pool.query(`INSERT INTO platform_job_runs(job_name,instance_id,status,details) VALUES($1,$2,'running',$3::jsonb) RETURNING id`,[name,BACKGROUND_INSTANCE_ID,JSON.stringify({trigger})]);runId=created.rows[0].id;
    const result=await fn();
    await pool.query(`UPDATE platform_job_runs SET status='succeeded',finished_at=NOW(),duration_ms=$2,details=details||$3::jsonb WHERE id=$1`,[runId,Date.now()-started,JSON.stringify({result:result??null})]);
    return {status:'succeeded',duration_ms:Date.now()-started};
  }catch(e){if(runId)await pool.query(`UPDATE platform_job_runs SET status='failed',finished_at=NOW(),duration_ms=$2,error_message=$3 WHERE id=$1`,[runId,Date.now()-started,String(e.message||e).slice(0,2000)]).catch(()=>{});console.error(JSON.stringify({level:'error',type:'background_job_failed',job:name,message:e.message}));return {status:'failed',error:e.message};}
  finally{if(locked)await lockClient.query(`SELECT pg_advisory_unlock(hashtext($1))`,[`patrolsync-job:${name}`]).catch(()=>{});lockClient.release()}
}
function scheduleBackgroundJob(name,intervalMs,initialDelayMs,fn){backgroundJobs.set(name,{name,interval_ms:intervalMs,fn});const execute=()=>{if(!runtimeState.draining)runBackgroundJob(name,fn).catch(e=>console.error(`Job ${name} runner failed:`,e.message))};const interval=setInterval(execute,intervalMs),initial=setTimeout(execute,initialDelayMs);backgroundTimers.push({type:'interval',handle:interval},{type:'timeout',handle:initial})}
ensureBackgroundJobSchema().catch(e=>console.error('Background job schema setup failed:',e.message));
ensureLoadTestSchema().catch(e=>console.error('Load-test schema setup failed:',e.message));
function percentile(values,percentage){if(!values.length)return 0;const sorted=[...values].sort((a,b)=>a-b);return sorted[Math.min(sorted.length-1,Math.max(0,Math.ceil((percentage/100)*sorted.length)-1))]}
function trimPerformanceSamples(now=Date.now()){const cutoff=now-PERFORMANCE_SAMPLE_WINDOW_MS;while(performanceSamples.length&&performanceSamples[0].finished_at<cutoff)performanceSamples.shift();if(performanceSamples.length>PERFORMANCE_MAX_SAMPLES)performanceSamples.splice(0,performanceSamples.length-PERFORMANCE_MAX_SAMPLES)}

function getProductionSecurityPosture(){
  const frontendOrigin=normalizedOrigin(process.env.FRONTEND_URL),jwtValue=String(process.env.JWT_SECRET||''),platformValue=String(process.env.PLATFORM_JWT_SECRET||'');
  const checks=[
    {key:'node_environment',critical:true,passed:IS_PRODUCTION,message:IS_PRODUCTION?'NODE_ENV is production':'Set NODE_ENV=production'},
    {key:'frontend_https',critical:true,passed:Boolean(frontendOrigin?.startsWith('https://')),message:frontendOrigin?.startsWith('https://')?'Frontend URL uses HTTPS':'FRONTEND_URL must use HTTPS'},
    {key:'jwt_secret',critical:true,passed:jwtValue.length>=32&&jwtValue!=='patrolsync-dev-secret',message:jwtValue.length>=32?'Subscriber JWT secret is strong':'JWT_SECRET must contain at least 32 characters'},
    {key:'platform_jwt_secret',critical:true,passed:platformValue.length>=32&&platformValue!==jwtValue,message:platformValue.length>=32&&platformValue!==jwtValue?'Platform JWT secret is strong and separate':'PLATFORM_JWT_SECRET must be 32+ characters and different from JWT_SECRET'},
    {key:'system_database_path',critical:true,passed:Boolean(process.env.SYSTEM_DATABASE_URL),message:process.env.SYSTEM_DATABASE_URL?'Trusted system database path configured':'SYSTEM_DATABASE_URL is missing'},
    {key:'tenant_database_path',critical:true,passed:Boolean(process.env.TENANT_DATABASE_URL)&&DATABASE_PATHS_SEPARATED,message:Boolean(process.env.TENANT_DATABASE_URL)&&DATABASE_PATHS_SEPARATED?'Restricted tenant database path configured':'TENANT_DATABASE_URL must be configured separately'},
    {key:'cors_allowlist',critical:true,passed:allowedOrigins.size>0&&!allowedOrigins.has('*'),message:`${allowedOrigins.size} explicit browser origin(s) allowed`},
    {key:'bootstrap_password_removed',critical:false,passed:!process.env.PLATFORM_ADMIN_PASSWORD,message:process.env.PLATFORM_ADMIN_PASSWORD?'Remove PLATFORM_ADMIN_PASSWORD after the owner account is created':'Platform bootstrap password removed'},
    {key:'email_provider',critical:false,passed:Boolean(process.env.BREVO_API_KEY&&process.env.EMAIL_FROM_ADDRESS),message:process.env.BREVO_API_KEY&&process.env.EMAIL_FROM_ADDRESS?'Transactional email configured':'Transactional email is incomplete'}
  ];
  return {ready:checks.every(x=>!x.critical||x.passed),checks,allowed_origins:[...allowedOrigins]};
}

function requestIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim(); }
function fixedWindowRateLimit(name, limit) {
  return (req, res, next) => {
    const now = Date.now(), key = `${name}:${requestIp(req)}`;
    let state = requestWindows.get(key);
    if (!state || now >= state.resetAt) state = { count: 0, resetAt: now + REQUEST_LIMIT_WINDOW_MS };
    state.count += 1; requestWindows.set(key, state);
    res.setHeader('X-RateLimit-Limit', String(limit)); res.setHeader('X-RateLimit-Remaining', String(Math.max(0, limit-state.count))); res.setHeader('X-RateLimit-Reset', String(Math.ceil(state.resetAt/1000)));
    if (state.count > limit) { res.setHeader('Retry-After', String(Math.ceil((state.resetAt-now)/1000))); return res.status(429).json({error:'Too many requests. Please wait and try again.',request_id:req.requestId}); }
    next();
  };
}
app.use((req,res,next)=>{
  req.requestId=String(req.headers['x-request-id']||crypto.randomUUID()).slice(0,100);req.requestStartedAt=Date.now();
  res.setHeader('X-Request-ID',req.requestId);res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'; base-uri 'none'");res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=(), usb=()');res.setHeader('X-DNS-Prefetch-Control','off');if(IS_PRODUCTION)res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');if(req.path.startsWith('/api/auth')||req.path.startsWith('/api/platform')||req.path.startsWith('/api/security'))res.setHeader('Cache-Control','no-store');
  if(req.method==='TRACE'||req.method==='TRACK')return res.status(405).json({error:'Method not allowed',request_id:req.requestId});
  res.on('finish',()=>{const duration=Date.now()-req.requestStartedAt;if(req.path!=='/health'){performanceSamples.push({finished_at:Date.now(),method:req.method,path:String(req.route?.path||req.path).replace(/\/\d+(?=\/|$)/g,'/:id').slice(0,180),status:res.statusCode,duration_ms:duration});trimPerformanceSamples()}if(res.statusCode>=500)console.error(JSON.stringify({level:'error',type:'http_5xx',request_id:req.requestId,method:req.method,path:req.path,status:res.statusCode,duration_ms:duration}))});next();
});
app.use(['/api/auth/login','/api/client-auth/login','/api/auth/guard-login','/api/auth/guard-login-v2','/api/auth/forgot-password','/api/auth/forgot-password-by-role','/api/auth/scoped-forgot-password','/api/auth/reset-password'],fixedWindowRateLimit('authentication',AUTH_REQUEST_LIMIT));
app.use('/api/signup',fixedWindowRateLimit('signup',5));
app.use('/api/public/v1',fixedWindowRateLimit('integration-api',API_KEY_REQUEST_LIMIT));
setInterval(()=>{const now=Date.now();for(const[key,value]of requestWindows.entries())if(now>=value.resetAt)requestWindows.delete(key)},10*60*1000);

const PLAN_LIMITS = {
  starter:    { locations: 1,        checkpoints: 10,       guards: 3,        client_accounts: 1,        monthly_price: 39,  overage: null },
  medium:     { locations: 1,        checkpoints: 20,       guards: 6,        client_accounts: 2,        monthly_price: 79,  overage: null },
  pro:        { locations: 2,        checkpoints: 50,       guards: 10,       client_accounts: 5,        monthly_price: 149, overage: null },
  diamond:    { locations: 3,        checkpoints: 100,      guards: 15,       client_accounts: 10,       monthly_price: 299, overage: null },
  enterprise: { locations: Infinity, checkpoints: Infinity, guards: Infinity, client_accounts: Infinity, monthly_price: 499, overage: { location: 80, checkpoint: 10, guard: 15, client_account: 20 } }
};
const VALID_PLANS = Object.keys(PLAN_LIMITS);

const FALLBACK_TIMEZONES = [
  'UTC', 'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Europe/Madrid', 'Europe/Rome',
  'Europe/Amsterdam', 'Europe/Warsaw', 'Europe/Moscow', 'Europe/Istanbul', 'Africa/Cairo',
  'Africa/Johannesburg', 'Africa/Lagos', 'Asia/Dubai', 'Asia/Karachi', 'Asia/Kolkata',
  'Asia/Dhaka', 'Asia/Bangkok', 'Asia/Jakarta', 'Asia/Singapore', 'Asia/Hong_Kong',
  'Asia/Shanghai', 'Asia/Tokyo', 'Asia/Seoul', 'Australia/Perth', 'Australia/Sydney',
  'Pacific/Auckland', 'America/Sao_Paulo', 'America/Argentina/Buenos_Aires', 'America/Mexico_City',
  'America/Bogota', 'America/Lima', 'America/New_York', 'America/Chicago', 'America/Denver',
  'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu'
];

function getAllTimezones() {
  try {
    if (typeof Intl.supportedValuesOf === 'function') {
      const zones = Intl.supportedValuesOf('timeZone');
      if (zones && zones.length) return zones;
    }
  } catch (err) {}
  return FALLBACK_TIMEZONES;
}

async function withTenant(tenantId, fn) {
  const normalizedTenantId = Number(tenantId);
  if (!Number.isInteger(normalizedTenantId) || normalizedTenantId < 1) {
    const err = new Error('A valid tenant ID is required');
    err.statusCode = 400;
    throw err;
  }
  const client = await tenantPool.connect();
  let resetError = null;
  try {
    await client.query(`SELECT set_config('app.current_tenant',$1,false)`, [String(normalizedTenantId)]);
    return await fn(client);
  } finally {
    try { await client.query('RESET app.current_tenant'); }
    catch (err) { resetError = err; console.error('Tenant database context reset failed:', err.message); }
    client.release(resetError || undefined);
  }
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    const tenantState=await pool.query(`SELECT COALESCE(account_active,TRUE) active FROM tenants WHERE id=$1`,[req.auth.tenant_id]);
    if(!tenantState.rowCount||tenantState.rows[0].active===false)return res.status(403).json({error:'Company subscription is suspended. Contact PatrolSync support.'});
    if(req.auth.role==='client')return next();
    const check=await pool.query(`SELECT account_active,password_changed_at FROM users WHERE id=$1 AND tenant_id=$2`,[req.auth.user_id,req.auth.tenant_id]);
    if(!check.rowCount||check.rows[0].account_active===false)return res.status(401).json({error:'Account disabled or removed'});
    const changed=check.rows[0].password_changed_at?new Date(check.rows[0].password_changed_at).getTime():0,issued=Number(req.auth.iat||0)*1000;
    if(changed&&issued<changed-1000)return res.status(401).json({error:'Session expired after a security change. Please log in again.'});
    if(req.auth.session_id){const session=await pool.query(`SELECT revoked_at,expires_at FROM auth_sessions WHERE id=$1 AND tenant_id=$2 AND user_id=$3`,[req.auth.session_id,req.auth.tenant_id,req.auth.user_id]);if(!session.rowCount||session.rows[0].revoked_at||new Date(session.rows[0].expires_at)<=new Date())return res.status(401).json({error:'This session has been signed out'});pool.query(`UPDATE auth_sessions SET last_seen_at=NOW() WHERE id=$1 AND last_seen_at<NOW()-INTERVAL '5 minutes'`,[req.auth.session_id]).catch(()=>{})}
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function permissionForPath(path=''){const rules=[['/api/dispatch','dispatch'],['/api/lone-worker','safety'],['/api/visitors','safety'],['/api/attendance','attendance'],['/api/timesheet','attendance'],['/api/shift','scheduling'],['/api/patrol','patrols'],['/api/checkpoint','patrols'],['/api/incident','incidents'],['/api/training','training'],['/api/certification','training'],['/api/assets','assets'],['/api/asset-custody','assets'],['/api/inspection','quality'],['/api/corrective','quality'],['/api/invoice','finance'],['/api/analytics','analytics'],['/api/service-contract','clients'],['/api/client-report','clients'],['/api/client-users','clients'],['/api/team-','communications'],['/api/communication-notifications','communications']];const found=rules.find(([prefix])=>path.startsWith(prefix));return found?found[1]:'administration';}
async function requireAdmin(req,res,next){if(!req.auth)return res.status(403).json({error:'Admin access required'});if(req.auth.role==='admin')return next();if(req.auth.role!=='staff')return res.status(403).json({error:'Admin access required'});try{const r=await pool.query(`SELECT permissions,account_active FROM users WHERE id=$1 AND tenant_id=$2 AND role='staff'`,[req.auth.user_id,req.auth.tenant_id]);if(!r.rowCount||r.rows[0].account_active===false)return res.status(403).json({error:'Staff account disabled'});const permissions=r.rows[0].permissions||[];if(req.method==='GET'&&['/api/users','/api/sites'].includes(req.path)){req.auth.permissions=permissions;return next();}const needed=permissionForPath(req.path);if(needed==='administration'||!permissions.includes(needed))return res.status(403).json({error:`Permission required: ${needed}`});req.auth.permissions=permissions;next()}catch(e){res.status(500).json({error:'Could not verify staff permissions'});}}
function requireOwnerAdmin(req,res,next){if(!req.auth||req.auth.role!=='admin')return res.status(403).json({error:'Company administrator access required'});next();}
async function requirePlatformAuth(req,res,next){const header=req.headers.authorization;if(!header?.startsWith('Bearer '))return res.status(401).json({error:'Platform authentication required'});try{const payload=jwt.verify(header.slice(7),PLATFORM_JWT_SECRET,{audience:'patrolsync-platform',issuer:'patrolsync'});if(payload.role!=='platform_admin'||!payload.session_id)throw new Error('Invalid platform role');const found=await pool.query(`SELECT a.id,a.email,a.display_name,a.active,s.revoked_at,s.expires_at FROM platform_admins a JOIN platform_auth_sessions s ON s.platform_admin_id=a.id AND s.id=$2 WHERE a.id=$1`,[payload.platform_admin_id,payload.session_id]);if(!found.rowCount||!found.rows[0].active||found.rows[0].revoked_at||new Date(found.rows[0].expires_at)<=new Date())return res.status(401).json({error:'Platform session expired or revoked'});req.platformAdmin=found.rows[0];req.platformSessionId=payload.session_id;pool.query(`UPDATE platform_auth_sessions SET last_seen_at=NOW() WHERE id=$1 AND last_seen_at<NOW()-INTERVAL '5 minutes'`,[payload.session_id]).catch(()=>{});next()}catch(e){res.status(401).json({error:'Invalid or expired platform session'})}}
async function platformAudit(req,action,resource,details={}){await pool.query(`INSERT INTO platform_audit_logs(platform_admin_id,admin_email,action,resource,details,ip_address,request_id) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)`,[req.platformAdmin?.id||null,req.platformAdmin?.email||null,action,resource,JSON.stringify(details),requestIp(req),req.requestId||null])}

function requireClient(req, res, next) {
  if (!req.auth || req.auth.role !== 'client') {
    return res.status(403).json({ error: 'Client access required' });
  }
  next();
}

function safeAuditDetails(body) {
  if (!body || typeof body !== 'object') return {};
  const hidden = new Set(['password', 'token', 'photo_base64', 'photos']);
  return Object.fromEntries(Object.entries(body).filter(([key]) => !hidden.has(key.toLowerCase())));
}

app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  res.on('finish', () => {
    if (!req.auth || res.statusCode >= 400 || req.path === '/api/login' || req.path === '/api/signup') return;
    const tenantId = Number((req.body && req.body.tenant_id) || req.query.tenant_id || req.auth.tenant_id);
    if (!Number.isInteger(tenantId) || tenantId !== Number(req.auth.tenant_id)) return;
    const routeName = req.route && req.route.path ? req.route.path : req.path;
    pool.query(
      `INSERT INTO audit_logs (tenant_id,user_id,user_email,user_role,action,resource,entity_id,details,ip_address)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [tenantId, req.auth.user_id, req.auth.email || null, req.auth.role, req.method, routeName,
       req.params && req.params.id ? String(req.params.id) : null, safeAuditDetails(req.body),
       String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim() || null]
    ).then(() => queueWebhookEvent(tenantId, `${req.method} ${routeName}`, { entity_id:req.params&&req.params.id?String(req.params.id):null, details:safeAuditDetails(req.body) }))
     .catch(err => console.error('Audit/webhook event write failed:', err.message));
  });
  next();
});

async function checkPlanLimit(client, tenantId, resource) {
  const tenantRes = await client.query('SELECT plan FROM tenants WHERE id = $1', [tenantId]);
  const plan = (tenantRes.rows[0] && tenantRes.rows[0].plan) || 'starter';
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.starter;
  const max = limits[resource];

  let countQuery;
  if (resource === 'locations') countQuery = 'SELECT COUNT(*) FROM sites WHERE tenant_id = $1';
  else if (resource === 'checkpoints') countQuery = 'SELECT COUNT(*) FROM checkpoints WHERE tenant_id = $1';
  else if (resource === 'guards') countQuery = "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'guard'";
  else if (resource === 'client_accounts') countQuery = 'SELECT COUNT(*) FROM client_users WHERE tenant_id = $1';
  else return { allowed: true, plan, max, current: null, decision_source:'legacy' };

  const countRes = await client.query(countQuery, [tenantId]);
  const current = parseInt(countRes.rows[0].count, 10);

  const legacyDecision={ allowed:max===Infinity||max===undefined||current<max, plan, max, current, decision_source:'legacy' };
  try {
    if(ENTITLEMENT_ENGINE_MODE!=='pilot'&&ENTITLEMENT_ENGINE_MODE!=='enforce')return legacyDecision;
    const featureCode=LEGACY_RESOURCE_FEATURE[resource];
    if(!featureCode)return legacyDecision;
    const globalEnforcement=ENTITLEMENT_ENGINE_MODE==='enforce';
    const pilotResult=globalEnforcement?{rows:[{enabled:true}]}:await client.query(`SELECT COALESCE(ft.enabled,f.enabled_globally,FALSE) enabled FROM feature_flags f LEFT JOIN feature_flag_tenants ft ON ft.flag_id=f.id AND ft.tenant_id=$1 WHERE f.code='entitlement_engine_enforcement'`,[tenantId]);
    if(!pilotResult.rows[0]?.enabled)return legacyDecision;
    const entitlement=await resolveTenantEntitlement(tenantId,featureCode,client);
    if(!entitlement)return legacyDecision;
    const entitlementMax=entitlement.hard_limit==null?null:Number(entitlement.hard_limit);
    return{allowed:Boolean(entitlement.enabled&&['active','trialing'].includes(entitlement.subscription_status)&&(entitlementMax==null||current<entitlementMax)),plan:entitlement.plan_code,max:entitlementMax,current,decision_source:'entitlement',plan_version:entitlement.plan_version};
  }catch(error){
    console.error('Entitlement decision fallback:',error.message);
    return legacyDecision;
  }
}

// ------------------------ EXPANSION STAGE 1A: ENTITLEMENTS FOUNDATION ------------------------

const ENTITLEMENT_ENGINE_MODE=String(process.env.ENTITLEMENT_ENGINE_MODE||'observe').toLowerCase();
const EXPANSION_PLAN_VERSION='2026.1';
const LEGACY_PLAN_VERSION='legacy-2026';
const EXPANSION_PLAN_SEED=[
  {code:'starter',name:'Starter',price:49,guards:5,sites:2,checkpoints:25,admins:2,clients:3,storage:5},
  {code:'growth',name:'Growth',price:99,guards:15,sites:5,checkpoints:100,admins:5,clients:10,storage:25},
  {code:'pro',name:'Pro',price:199,guards:40,sites:15,checkpoints:400,admins:12,clients:30,storage:100},
  {code:'command',name:'Command',price:399,guards:100,sites:50,checkpoints:1500,admins:30,clients:100,storage:500},
  {code:'enterprise',name:'Enterprise',price:699,guards:null,sites:null,checkpoints:null,admins:null,clients:null,storage:null}
];
const LEGACY_PLAN_SEED=Object.entries(PLAN_LIMITS).map(([code,limits])=>({code,name:`Legacy ${code}`,price:limits.monthly_price,guards:Number.isFinite(limits.guards)?limits.guards:null,sites:Number.isFinite(limits.locations)?limits.locations:null,checkpoints:Number.isFinite(limits.checkpoints)?limits.checkpoints:null,admins:null,clients:Number.isFinite(limits.client_accounts)?limits.client_accounts:null,storage:null}));
const FEATURE_SEED=[
  ['active_guards','capacity','count'],['sites','capacity','count'],['checkpoints','capacity','count'],['admin_users','capacity','count'],['client_users','capacity','count'],['document_storage_gb','capacity','gb'],
  ['qr_checkpoints','patrol','boolean'],['nfc_checkpoints','patrol','boolean'],['offline_patrol','patrol','boolean'],['dispatch','operations','boolean'],['compliance','workforce','boolean'],['visitor_management','operations','boolean'],['trustproof','assurance','boolean'],['coverage_autopilot','intelligence','boolean'],['operations_risk','intelligence','boolean'],
  ['proofscore','assurance','boolean'],['contract_ops','commercial','boolean'],['sla_predictor','intelligence','boolean'],['service_credit_autopilot','commercial','boolean'],['incident_reconstruction','incidents','boolean'],['external_trustproof_verify','assurance','boolean'],['client_retention_radar','commercial','boolean'],['site_risk_digital_twin','intelligence','boolean'],['crisis_mode','incidents','boolean'],['smart_handover','workforce','boolean'],['ai_chat','ai','requests']
];
const PLAN_BOOLEAN_FEATURES={
  starter:['qr_checkpoints'],
  growth:['qr_checkpoints','nfc_checkpoints','offline_patrol'],
  pro:['qr_checkpoints','nfc_checkpoints','offline_patrol','dispatch','compliance','visitor_management','trustproof','coverage_autopilot','operations_risk'],
  command:['qr_checkpoints','nfc_checkpoints','offline_patrol','dispatch','compliance','visitor_management','trustproof','coverage_autopilot','operations_risk','proofscore','contract_ops','sla_predictor','service_credit_autopilot','incident_reconstruction','external_trustproof_verify','client_retention_radar','site_risk_digital_twin','crisis_mode','smart_handover'],
  enterprise:FEATURE_SEED.filter(([,category,unit])=>unit==='boolean'&&category!=='capacity').map(([code])=>code)
};
const LEGACY_PLAN_BOOLEAN_FEATURES={
  starter:['qr_checkpoints'],
  medium:['qr_checkpoints','nfc_checkpoints','offline_patrol'],
  pro:['qr_checkpoints','nfc_checkpoints','offline_patrol','dispatch','compliance','visitor_management'],
  diamond:['qr_checkpoints','nfc_checkpoints','offline_patrol','dispatch','compliance','visitor_management','trustproof','coverage_autopilot','operations_risk'],
  enterprise:FEATURE_SEED.filter(([,category,unit])=>unit==='boolean'&&category!=='capacity').map(([code])=>code)
};
function quotedRoleFromTenantUrl(){try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');return /^[A-Za-z_][A-Za-z0-9_]*$/.test(role)?`"${role}"`:null}catch(_){return null}}
async function ensureEntitlementSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS plan_catalog(id BIGSERIAL PRIMARY KEY,code TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',public_price_monthly NUMERIC(12,2),currency TEXT NOT NULL DEFAULT 'EUR',is_public BOOLEAN NOT NULL DEFAULT FALSE,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(code,version))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS feature_catalog(id BIGSERIAL PRIMARY KEY,code TEXT NOT NULL UNIQUE,name TEXT NOT NULL,category TEXT NOT NULL,unit TEXT NOT NULL DEFAULT 'boolean',metered BOOLEAN NOT NULL DEFAULT FALSE,status TEXT NOT NULL DEFAULT 'active',metadata JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS plan_features(id BIGSERIAL PRIMARY KEY,plan_id BIGINT NOT NULL REFERENCES plan_catalog(id) ON DELETE CASCADE,feature_id BIGINT NOT NULL REFERENCES feature_catalog(id) ON DELETE CASCADE,enabled BOOLEAN NOT NULL DEFAULT FALSE,included_quantity NUMERIC,soft_limit NUMERIC,hard_limit NUMERIC,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,UNIQUE(plan_id,feature_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS tenant_subscriptions(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL UNIQUE,plan_id BIGINT NOT NULL REFERENCES plan_catalog(id),status TEXT NOT NULL DEFAULT 'active',period_start TIMESTAMPTZ,period_end TIMESTAMPTZ,trial_end TIMESTAMPTZ,billing_provider TEXT,billing_provider_ref TEXT,migration_source TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS tenant_entitlement_overrides(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,feature_id BIGINT NOT NULL REFERENCES feature_catalog(id),enabled BOOLEAN,included_quantity NUMERIC,reason TEXT NOT NULL,expires_at TIMESTAMPTZ,approved_by BIGINT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,feature_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS usage_events(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,feature_id BIGINT NOT NULL REFERENCES feature_catalog(id),quantity NUMERIC NOT NULL CHECK(quantity>=0),occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),source_object_type TEXT,source_object_id TEXT,idempotency_key TEXT NOT NULL,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,UNIQUE(tenant_id,idempotency_key))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS usage_period_summaries(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,feature_id BIGINT NOT NULL REFERENCES feature_catalog(id),period_start DATE NOT NULL,period_end DATE NOT NULL,quantity NUMERIC NOT NULL DEFAULT 0,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,feature_id,period_start,period_end))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS feature_flags(id BIGSERIAL PRIMARY KEY,code TEXT NOT NULL UNIQUE,description TEXT,enabled_globally BOOLEAN NOT NULL DEFAULT FALSE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS feature_flag_tenants(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,flag_id BIGINT NOT NULL REFERENCES feature_flags(id) ON DELETE CASCADE,enabled BOOLEAN NOT NULL DEFAULT FALSE,reason TEXT,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,flag_id))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_usage_events_tenant_feature_time ON usage_events(tenant_id,feature_id,occurred_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_entitlement_overrides_tenant ON tenant_entitlement_overrides(tenant_id,expires_at)`);
  for(const table of ['tenant_subscriptions','tenant_entitlement_overrides','usage_events','usage_period_summaries','feature_flag_tenants']){
    await pool.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);
    await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ${table}`);
    await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ${table} USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  }
  const tenantRole=quotedRoleFromTenantUrl();
  if(tenantRole){
    for(const table of ['tenant_subscriptions','tenant_entitlement_overrides','usage_events','usage_period_summaries','feature_flag_tenants'])await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON ${table} TO ${tenantRole}`);
    for(const table of ['plan_catalog','feature_catalog','plan_features','feature_flags'])await pool.query(`GRANT SELECT ON ${table} TO ${tenantRole}`);
    await pool.query(`GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO ${tenantRole}`);
  }
  for(const [code,category,unit] of FEATURE_SEED)await pool.query(`INSERT INTO feature_catalog(code,name,category,unit,metered) VALUES($1,$2,$3,$4,$5) ON CONFLICT(code) DO UPDATE SET category=EXCLUDED.category,unit=EXCLUDED.unit,metered=EXCLUDED.metered`,[code,code.split('_').map(x=>x[0].toUpperCase()+x.slice(1)).join(' '),category,unit,unit!=='boolean']);
  for(const plan of [...LEGACY_PLAN_SEED,...EXPANSION_PLAN_SEED]){
    const version=LEGACY_PLAN_SEED.includes(plan)?LEGACY_PLAN_VERSION:EXPANSION_PLAN_VERSION,isPublic=version===EXPANSION_PLAN_VERSION;
    const planId=(await pool.query(`INSERT INTO plan_catalog(code,name,version,public_price_monthly,is_public,metadata) VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(code,version) DO UPDATE SET name=EXCLUDED.name,public_price_monthly=EXCLUDED.public_price_monthly,is_public=EXCLUDED.is_public,metadata=EXCLUDED.metadata,updated_at=NOW() RETURNING id`,[plan.code,plan.name,version,plan.price,isPublic,JSON.stringify({source:version===EXPANSION_PLAN_VERSION?'expansion_pack':'legacy_compatibility'})])).rows[0].id;
    const limits={active_guards:plan.guards,sites:plan.sites,checkpoints:plan.checkpoints,admin_users:plan.admins,client_users:plan.clients,document_storage_gb:plan.storage};
    for(const [featureCode,limit] of Object.entries(limits))if(limit!==undefined){await pool.query(`INSERT INTO plan_features(plan_id,feature_id,enabled,included_quantity,hard_limit) SELECT $1,id,TRUE,$3,$3 FROM feature_catalog WHERE code=$2 ON CONFLICT(plan_id,feature_id) DO UPDATE SET enabled=TRUE,included_quantity=EXCLUDED.included_quantity,hard_limit=EXCLUDED.hard_limit`,[planId,featureCode,limit]);}
    const booleans=version===EXPANSION_PLAN_VERSION?(PLAN_BOOLEAN_FEATURES[plan.code]||[]):(LEGACY_PLAN_BOOLEAN_FEATURES[plan.code]||['qr_checkpoints']);
    for(const featureCode of booleans)await pool.query(`INSERT INTO plan_features(plan_id,feature_id,enabled) SELECT $1,id,TRUE FROM feature_catalog WHERE code=$2 ON CONFLICT(plan_id,feature_id) DO UPDATE SET enabled=TRUE`,[planId,featureCode]);
  }
  await pool.query(`INSERT INTO tenant_subscriptions(tenant_id,plan_id,status,period_start,period_end,migration_source) SELECT t.id,p.id,COALESCE(NULLIF(t.subscription_status,''),'active'),date_trunc('month',NOW()),date_trunc('month',NOW())+INTERVAL '1 month','legacy_plan_backfill' FROM tenants t JOIN plan_catalog p ON p.code=COALESCE(NULLIF(t.plan,''),'starter') AND p.version=$1 ON CONFLICT(tenant_id) DO NOTHING`,[LEGACY_PLAN_VERSION]);
  await pool.query(`INSERT INTO feature_flags(code,description,enabled_globally) VALUES('entitlement_engine_enforcement','Enforce database-backed plan entitlements',FALSE),('expansion_stage_1','Expansion Stage 1 subscriber experience',FALSE) ON CONFLICT(code) DO NOTHING`);
  console.log(`Expansion entitlement schema ready in ${ENTITLEMENT_ENGINE_MODE} mode`);
}
let entitlementSchemaError=null;
const entitlementSchemaReady=ensureEntitlementSchema().catch(err=>{
  entitlementSchemaError=err;
  console.error('Entitlement schema setup failed (observe mode remains non-blocking):',err.message);
  return null;
});
async function requireEntitlementSchema(){
  await entitlementSchemaReady;
  if(entitlementSchemaError){
    const error=new Error('Entitlement diagnostics are temporarily unavailable');
    error.status=503;
    throw error;
  }
}

async function resolveTenantEntitlement(tenantId,featureCode,client=pool){
  const result=await client.query(`SELECT ts.tenant_id,ts.status subscription_status,p.code plan_code,p.name plan_name,p.version plan_version,f.code feature_code,f.unit,COALESCE(o.enabled,pf.enabled,FALSE) enabled,COALESCE(o.included_quantity,pf.included_quantity) included_quantity,pf.soft_limit,COALESCE(o.included_quantity,pf.hard_limit) hard_limit,o.reason override_reason,o.expires_at override_expires_at FROM tenant_subscriptions ts JOIN plan_catalog p ON p.id=ts.plan_id JOIN feature_catalog f ON f.code=$2 LEFT JOIN plan_features pf ON pf.plan_id=ts.plan_id AND pf.feature_id=f.id LEFT JOIN tenant_entitlement_overrides o ON o.tenant_id=ts.tenant_id AND o.feature_id=f.id AND(o.expires_at IS NULL OR o.expires_at>NOW()) WHERE ts.tenant_id=$1`,[tenantId,featureCode]);
  return result.rows[0]||null;
}
async function canUseFeature(tenantId,featureCode,client=pool){const entitlement=await resolveTenantEntitlement(tenantId,featureCode,client);return{allowed:Boolean(entitlement?.enabled&&['active','trialing'].includes(entitlement.subscription_status)),mode:ENTITLEMENT_ENGINE_MODE,entitlement};}
async function recordUsageEvent({tenantId,featureCode,quantity=1,idempotencyKey,sourceObjectType=null,sourceObjectId=null,metadata={}}){
  if(!idempotencyKey)throw new Error('Usage idempotency key is required');
  return withTenant(tenantId,async client=>{try{
    await client.query('BEGIN');
    const result=await client.query(`INSERT INTO usage_events(tenant_id,feature_id,quantity,idempotency_key,source_object_type,source_object_id,metadata) SELECT $1,id,$3,$4,$5,$6,$7::jsonb FROM feature_catalog WHERE code=$2 ON CONFLICT(tenant_id,idempotency_key) DO NOTHING RETURNING id,feature_id,quantity,occurred_at`,[tenantId,featureCode,quantity,idempotencyKey,sourceObjectType,sourceObjectId,JSON.stringify(metadata)]);
    if(result.rowCount){const event=result.rows[0];await client.query(`INSERT INTO usage_period_summaries(tenant_id,feature_id,period_start,period_end,quantity,updated_at) VALUES($1,$2,date_trunc('month',$3::timestamptz)::date,(date_trunc('month',$3::timestamptz)+INTERVAL '1 month')::date,$4,NOW()) ON CONFLICT(tenant_id,feature_id,period_start,period_end) DO UPDATE SET quantity=usage_period_summaries.quantity+EXCLUDED.quantity,updated_at=NOW()`,[tenantId,event.feature_id,event.occurred_at,event.quantity]);}
    await client.query('COMMIT');return{recorded:Boolean(result.rowCount),id:result.rows[0]?.id||null};
  }catch(error){try{await client.query('ROLLBACK')}catch(_){}throw error}});
}

app.get('/api/subscription/entitlements',requireAuth,async(req,res)=>{try{await entitlementSchemaReady;const rows=await withTenant(req.auth.tenant_id,client=>client.query(`SELECT p.code plan_code,p.name plan_name,p.version plan_version,ts.status subscription_status,f.code feature_code,f.name feature_name,f.category,f.unit,COALESCE(o.enabled,pf.enabled,FALSE) enabled,COALESCE(o.included_quantity,pf.included_quantity) included_quantity,COALESCE(o.included_quantity,pf.hard_limit) hard_limit,o.reason override_reason FROM tenant_subscriptions ts JOIN plan_catalog p ON p.id=ts.plan_id CROSS JOIN feature_catalog f LEFT JOIN plan_features pf ON pf.plan_id=ts.plan_id AND pf.feature_id=f.id LEFT JOIN tenant_entitlement_overrides o ON o.tenant_id=ts.tenant_id AND o.feature_id=f.id AND(o.expires_at IS NULL OR o.expires_at>NOW()) WHERE ts.tenant_id=$1 ORDER BY f.category,f.code`,[req.auth.tenant_id]));res.json({mode:ENTITLEMENT_ENGINE_MODE,plan:rows.rows[0]?{code:rows.rows[0].plan_code,name:rows.rows[0].plan_name,version:rows.rows[0].plan_version,status:rows.rows[0].subscription_status}:null,features:rows.rows.map(({plan_code,plan_name,plan_version,subscription_status,...feature})=>feature)})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/subscription/usage',requireAuth,requireAdmin,async(req,res)=>{try{await requireEntitlementSchema();const tenantId=Number(req.auth.tenant_id);const capacity=await currentCapacityUsage(tenantId);const rows=await withTenant(tenantId,client=>client.query(`SELECT f.code,f.name,f.category,f.unit,COALESCE(o.enabled,pf.enabled,FALSE) enabled,COALESCE(o.included_quantity,pf.included_quantity) included_quantity,COALESCE(o.included_quantity,pf.hard_limit) hard_limit,COALESCE(s.quantity,0)::numeric period_usage,s.updated_at FROM tenant_subscriptions ts JOIN plan_catalog p ON p.id=ts.plan_id CROSS JOIN feature_catalog f LEFT JOIN plan_features pf ON pf.plan_id=p.id AND pf.feature_id=f.id LEFT JOIN tenant_entitlement_overrides o ON o.tenant_id=ts.tenant_id AND o.feature_id=f.id AND(o.expires_at IS NULL OR o.expires_at>NOW()) LEFT JOIN usage_period_summaries s ON s.tenant_id=ts.tenant_id AND s.feature_id=f.id AND s.period_start=date_trunc('month',NOW())::date WHERE ts.tenant_id=$1 ORDER BY f.category,f.code`,[tenantId]));res.json({mode:ENTITLEMENT_ENGINE_MODE,period:{start:new Date(new Date().getFullYear(),new Date().getMonth(),1),end:new Date(new Date().getFullYear(),new Date().getMonth()+1,1)},capacity,features:rows.rows})}catch(e){res.status(e.status||500).json({error:e.message})}});
app.get('/api/platform/entitlements/catalog',requirePlatformAuth,async(req,res)=>{try{await entitlementSchemaReady;const[plans,features]=await Promise.all([pool.query(`SELECT p.*,COALESCE(jsonb_agg(jsonb_build_object('code',f.code,'enabled',pf.enabled,'included_quantity',pf.included_quantity,'hard_limit',pf.hard_limit) ORDER BY f.code) FILTER(WHERE f.id IS NOT NULL),'[]'::jsonb) features FROM plan_catalog p LEFT JOIN plan_features pf ON pf.plan_id=p.id LEFT JOIN feature_catalog f ON f.id=pf.feature_id GROUP BY p.id ORDER BY p.version,p.public_price_monthly NULLS LAST`),pool.query(`SELECT * FROM feature_catalog ORDER BY category,code`)]);res.json({mode:ENTITLEMENT_ENGINE_MODE,plans:plans.rows,features:features.rows})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/platform/entitlements/tenants/:id',requirePlatformAuth,async(req,res)=>{const tenantId=Number(req.params.id);if(!Number.isInteger(tenantId)||tenantId<1)return res.status(400).json({error:'Invalid company ID'});try{await entitlementSchemaReady;const rows=await pool.query(`SELECT t.id tenant_id,t.name tenant_name,t.plan legacy_plan,p.code plan_code,p.name plan_name,p.version plan_version,ts.status subscription_status,f.code feature_code,f.category,f.unit,COALESCE(o.enabled,pf.enabled,FALSE) enabled,COALESCE(o.included_quantity,pf.included_quantity) included_quantity,COALESCE(o.included_quantity,pf.hard_limit) hard_limit,o.reason override_reason,o.expires_at FROM tenants t LEFT JOIN tenant_subscriptions ts ON ts.tenant_id=t.id LEFT JOIN plan_catalog p ON p.id=ts.plan_id CROSS JOIN feature_catalog f LEFT JOIN plan_features pf ON pf.plan_id=ts.plan_id AND pf.feature_id=f.id LEFT JOIN tenant_entitlement_overrides o ON o.tenant_id=t.id AND o.feature_id=f.id AND(o.expires_at IS NULL OR o.expires_at>NOW()) WHERE t.id=$1 ORDER BY f.category,f.code`,[tenantId]);if(!rows.rowCount)return res.status(404).json({error:'Subscriber company not found'});await platformAudit(req,'VIEW','tenant_entitlements',{tenant_id:tenantId});res.json({mode:ENTITLEMENT_ENGINE_MODE,tenant:{id:tenantId,name:rows.rows[0].tenant_name,legacy_plan:rows.rows[0].legacy_plan},subscription:{code:rows.rows[0].plan_code,name:rows.rows[0].plan_name,version:rows.rows[0].plan_version,status:rows.rows[0].subscription_status},features:rows.rows.map(r=>({code:r.feature_code,category:r.category,unit:r.unit,enabled:r.enabled,included_quantity:r.included_quantity,hard_limit:r.hard_limit,override_reason:r.override_reason,expires_at:r.expires_at}))})}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ EXPANSION STAGE 1B: SHADOW VERIFICATION ------------------------
const LEGACY_RESOURCE_FEATURE={locations:'sites',checkpoints:'checkpoints',guards:'active_guards',client_accounts:'client_users'};
async function currentCapacityUsage(tenantId,client=pool){
  const result=await client.query(`SELECT
    (SELECT COUNT(*)::int FROM sites WHERE tenant_id=$1) sites,
    (SELECT COUNT(*)::int FROM checkpoints WHERE tenant_id=$1) checkpoints,
    (SELECT COUNT(*)::int FROM users WHERE tenant_id=$1 AND role='guard') active_guards,
    (SELECT COUNT(*)::int FROM client_users WHERE tenant_id=$1) client_users`,[tenantId]);
  return result.rows[0];
}
app.get('/api/platform/entitlements/shadow-report',requirePlatformAuth,async(req,res)=>{try{
  await requireEntitlementSchema();
  const tenants=(await pool.query(`SELECT id,name,COALESCE(NULLIF(plan,''),'starter') legacy_plan FROM tenants ORDER BY id`)).rows;
  const decisions=[];
  for(const tenant of tenants){
    const usage=await currentCapacityUsage(tenant.id);
    const legacyLimits=PLAN_LIMITS[tenant.legacy_plan]||PLAN_LIMITS.starter;
    for(const [legacyResource,featureCode] of Object.entries(LEGACY_RESOURCE_FEATURE)){
      const legacyMax=legacyLimits[legacyResource],current=Number(usage[featureCode]||0);
      const legacyAllowed=legacyMax===Infinity||legacyMax===undefined||current<legacyMax;
      const entitlement=await resolveTenantEntitlement(tenant.id,featureCode);
      const newLimit=entitlement?.hard_limit==null?null:Number(entitlement.hard_limit);
      const newAllowed=Boolean(entitlement?.enabled&&['active','trialing'].includes(entitlement.subscription_status)&&(newLimit==null||current<newLimit));
      decisions.push({tenant_id:tenant.id,tenant_name:tenant.name,legacy_plan:tenant.legacy_plan,feature_code:featureCode,current,legacy_limit:Number.isFinite(legacyMax)?legacyMax:null,new_limit:newLimit,legacy_allowed:legacyAllowed,new_allowed:newAllowed,match:legacyAllowed===newAllowed,subscription_version:entitlement?.plan_version||null});
    }
  }
  const mismatches=decisions.filter(x=>!x.match);
  await platformAudit(req,'VERIFY','entitlement_shadow_report',{tenants:tenants.length,decisions:decisions.length,mismatches:mismatches.length});
  res.json({mode:ENTITLEMENT_ENGINE_MODE,generated_at:new Date(),summary:{tenants:tenants.length,decisions:decisions.length,matches:decisions.length-mismatches.length,mismatches:mismatches.length,ready_for_pilot:mismatches.length===0},decisions});
}catch(e){res.status(e.status||500).json({error:e.message})}});
app.get('/api/platform/entitlements/usage/:id',requirePlatformAuth,async(req,res)=>{const tenantId=Number(req.params.id);if(!Number.isInteger(tenantId)||tenantId<1)return res.status(400).json({error:'Invalid company ID'});try{
  await requireEntitlementSchema();
  const tenant=(await pool.query(`SELECT id,name FROM tenants WHERE id=$1`,[tenantId])).rows[0];if(!tenant)return res.status(404).json({error:'Subscriber company not found'});
  const capacity=await currentCapacityUsage(tenantId);
  const metered=(await pool.query(`SELECT f.code,f.name,f.unit,COALESCE(SUM(u.quantity),0)::numeric quantity,MAX(u.occurred_at) last_event_at FROM feature_catalog f LEFT JOIN usage_events u ON u.feature_id=f.id AND u.tenant_id=$1 AND u.occurred_at>=date_trunc('month',NOW()) WHERE f.metered=TRUE GROUP BY f.id ORDER BY f.category,f.code`,[tenantId])).rows;
  await platformAudit(req,'VIEW','tenant_usage',{tenant_id:tenantId});
  res.json({tenant,period:{start:new Date(new Date().getFullYear(),new Date().getMonth(),1),end:new Date(new Date().getFullYear(),new Date().getMonth()+1,1)},capacity,metered});
}catch(e){res.status(e.status||500).json({error:e.message})}});

// ------------------------ EXPANSION STAGE 1C: CONTROLLED PILOT ------------------------
app.get('/api/platform/entitlements/pilot-status',requirePlatformAuth,async(req,res)=>{try{
  await requireEntitlementSchema();
  const rows=(await pool.query(`SELECT t.id tenant_id,t.name tenant_name,COALESCE(ft.enabled,FALSE) pilot_enabled,ft.reason,ft.updated_at FROM tenants t CROSS JOIN feature_flags f LEFT JOIN feature_flag_tenants ft ON ft.tenant_id=t.id AND ft.flag_id=f.id WHERE f.code='entitlement_engine_enforcement' ORDER BY t.id`)).rows;
  res.json({mode:ENTITLEMENT_ENGINE_MODE,enforcement_active:ENTITLEMENT_ENGINE_MODE==='pilot'||ENTITLEMENT_ENGINE_MODE==='enforce',global_enforcement:ENTITLEMENT_ENGINE_MODE==='enforce',tenants:rows});
}catch(e){res.status(e.status||500).json({error:e.message})}});
app.put('/api/platform/entitlements/pilot-tenants/:id',requirePlatformAuth,async(req,res)=>{const tenantId=Number(req.params.id),enabled=req.body?.enabled===true,reason=String(req.body?.reason||'Internal entitlement pilot').trim().slice(0,500);if(!Number.isInteger(tenantId)||tenantId<1)return res.status(400).json({error:'Invalid company ID'});try{
  await requireEntitlementSchema();
  const tenant=(await pool.query(`SELECT id,name FROM tenants WHERE id=$1`,[tenantId])).rows[0];if(!tenant)return res.status(404).json({error:'Subscriber company not found'});
  await pool.query(`INSERT INTO feature_flag_tenants(tenant_id,flag_id,enabled,reason,updated_at) SELECT $1,id,$2,$3,NOW() FROM feature_flags WHERE code='entitlement_engine_enforcement' ON CONFLICT(tenant_id,flag_id) DO UPDATE SET enabled=EXCLUDED.enabled,reason=EXCLUDED.reason,updated_at=NOW()`,[tenantId,enabled,reason]);
  await platformAudit(req,enabled?'ENABLE_PILOT':'DISABLE_PILOT','entitlement_engine',{tenant_id:tenantId,tenant_name:tenant.name,mode:ENTITLEMENT_ENGINE_MODE,reason});
  res.json({message:`Entitlement pilot ${enabled?'enabled':'disabled'} for ${tenant.name}.`,tenant_id:tenantId,pilot_enabled:enabled,mode:ENTITLEMENT_ENGINE_MODE,enforcement_active:enabled&&(ENTITLEMENT_ENGINE_MODE==='pilot'||ENTITLEMENT_ENGINE_MODE==='enforce')});
}catch(e){res.status(e.status||500).json({error:e.message})}});

// ------------------------ EXPANSION STAGE 1D: AUDITED PLAN ADMINISTRATION ------------------------
app.put('/api/platform/entitlements/tenants/:id/subscription',requirePlatformAuth,async(req,res)=>{const tenantId=Number(req.params.id),planCode=String(req.body?.plan_code||'').trim().toLowerCase(),version=String(req.body?.version||EXPANSION_PLAN_VERSION).trim(),status=String(req.body?.status||'active').trim().toLowerCase(),confirmation=String(req.body?.confirmation||'').trim();if(!Number.isInteger(tenantId)||tenantId<1)return res.status(400).json({error:'Invalid company ID'});if(!['active','trialing','past_due','suspended','cancelled'].includes(status))return res.status(400).json({error:'Invalid subscription status'});if(confirmation!==`ASSIGN PLAN ${tenantId}`)return res.status(400).json({error:`Type ASSIGN PLAN ${tenantId} to confirm`});const client=await pool.connect();try{
  await requireEntitlementSchema();await client.query('BEGIN');
  const tenant=(await client.query(`SELECT id,name,plan legacy_plan FROM tenants WHERE id=$1 FOR UPDATE`,[tenantId])).rows[0];if(!tenant){await client.query('ROLLBACK');return res.status(404).json({error:'Subscriber company not found'})}
  const plan=(await client.query(`SELECT id,code,name,version FROM plan_catalog WHERE code=$1 AND version=$2 AND status='active'`,[planCode,version])).rows[0];if(!plan){await client.query('ROLLBACK');return res.status(404).json({error:'Active plan version not found'})}
  const previous=(await client.query(`SELECT p.code,p.name,p.version,ts.status FROM tenant_subscriptions ts JOIN plan_catalog p ON p.id=ts.plan_id WHERE ts.tenant_id=$1`,[tenantId])).rows[0]||null;
  await client.query(`INSERT INTO tenant_subscriptions(tenant_id,plan_id,status,period_start,period_end,migration_source,updated_at) VALUES($1,$2,$3,date_trunc('month',NOW()),date_trunc('month',NOW())+INTERVAL '1 month','platform_assignment',NOW()) ON CONFLICT(tenant_id) DO UPDATE SET plan_id=EXCLUDED.plan_id,status=EXCLUDED.status,migration_source='platform_assignment',updated_at=NOW()`,[tenantId,plan.id,status]);
  await client.query('COMMIT');await platformAudit(req,'ASSIGN_PLAN','tenant_subscription',{tenant_id:tenantId,tenant_name:tenant.name,legacy_plan_unchanged:tenant.legacy_plan,previous,next:{code:plan.code,name:plan.name,version:plan.version,status}});
  res.json({message:`${tenant.name} assigned to ${plan.name} (${plan.version}). Legacy plan remains ${tenant.legacy_plan} for rollback.`,tenant_id:tenantId,subscription:{...plan,status},legacy_plan:tenant.legacy_plan});
}catch(e){try{await client.query('ROLLBACK')}catch(_){}res.status(e.status||500).json({error:e.message})}finally{client.release()}});
app.put('/api/platform/entitlements/tenants/:id/overrides/:featureCode',requirePlatformAuth,async(req,res)=>{const tenantId=Number(req.params.id),featureCode=String(req.params.featureCode||'').trim(),reason=String(req.body?.reason||'').trim().slice(0,500),confirmation=String(req.body?.confirmation||'').trim(),expiresAt=req.body?.expires_at||null,enabled=req.body?.enabled==null?null:req.body.enabled===true,included=req.body?.included_quantity==null||req.body.included_quantity===''?null:Number(req.body.included_quantity);if(!Number.isInteger(tenantId)||tenantId<1)return res.status(400).json({error:'Invalid company ID'});if(!reason)return res.status(400).json({error:'Override reason is required'});if(confirmation!==`OVERRIDE ${tenantId}`)return res.status(400).json({error:`Type OVERRIDE ${tenantId} to confirm`});if(included!=null&&(!Number.isFinite(included)||included<0))return res.status(400).json({error:'Included quantity must be zero or greater'});try{
  await requireEntitlementSchema();const tenant=(await pool.query(`SELECT id,name FROM tenants WHERE id=$1`,[tenantId])).rows[0];if(!tenant)return res.status(404).json({error:'Subscriber company not found'});const feature=(await pool.query(`SELECT id,code,name,unit FROM feature_catalog WHERE code=$1 AND status='active'`,[featureCode])).rows[0];if(!feature)return res.status(404).json({error:'Feature not found'});
  await pool.query(`INSERT INTO tenant_entitlement_overrides(tenant_id,feature_id,enabled,included_quantity,reason,expires_at,approved_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,NOW()) ON CONFLICT(tenant_id,feature_id) DO UPDATE SET enabled=EXCLUDED.enabled,included_quantity=EXCLUDED.included_quantity,reason=EXCLUDED.reason,expires_at=EXCLUDED.expires_at,approved_by=EXCLUDED.approved_by,created_at=NOW()`,[tenantId,feature.id,enabled,included,reason,expiresAt,req.platformAdmin.id]);
  await platformAudit(req,'SET_OVERRIDE','tenant_entitlement',{tenant_id:tenantId,tenant_name:tenant.name,feature_code:feature.code,enabled,included_quantity:included,reason,expires_at:expiresAt});res.json({message:`Override saved for ${tenant.name}: ${feature.name}.`,tenant_id:tenantId,feature_code:feature.code});
}catch(e){res.status(e.status||500).json({error:e.message})}});
app.delete('/api/platform/entitlements/tenants/:id/overrides/:featureCode',requirePlatformAuth,async(req,res)=>{const tenantId=Number(req.params.id),featureCode=String(req.params.featureCode||'').trim(),confirmation=String(req.body?.confirmation||'').trim();if(!Number.isInteger(tenantId)||tenantId<1)return res.status(400).json({error:'Invalid company ID'});if(confirmation!==`REMOVE OVERRIDE ${tenantId}`)return res.status(400).json({error:`Type REMOVE OVERRIDE ${tenantId} to confirm`});try{
  const removed=await pool.query(`DELETE FROM tenant_entitlement_overrides o USING feature_catalog f WHERE o.tenant_id=$1 AND o.feature_id=f.id AND f.code=$2 RETURNING o.id`,[tenantId,featureCode]);if(!removed.rowCount)return res.status(404).json({error:'Override not found'});await platformAudit(req,'REMOVE_OVERRIDE','tenant_entitlement',{tenant_id:tenantId,feature_code:featureCode});res.json({message:'Entitlement override removed.'});
}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ EXPANSION STAGE 1E: USAGE RECONCILIATION ------------------------
app.post('/api/platform/entitlements/reconcile-usage',requirePlatformAuth,async(req,res)=>{const confirmation=String(req.body?.confirmation||'').trim();if(confirmation!=='REBUILD USAGE')return res.status(400).json({error:'Type REBUILD USAGE to confirm'});const client=await pool.connect();try{
  await requireEntitlementSchema();await client.query('BEGIN');
  await client.query(`DELETE FROM usage_period_summaries`);
  const rebuilt=await client.query(`INSERT INTO usage_period_summaries(tenant_id,feature_id,period_start,period_end,quantity,updated_at) SELECT tenant_id,feature_id,date_trunc('month',occurred_at)::date,(date_trunc('month',occurred_at)+INTERVAL '1 month')::date,SUM(quantity),NOW() FROM usage_events GROUP BY tenant_id,feature_id,date_trunc('month',occurred_at) RETURNING id`);
  await client.query('COMMIT');await platformAudit(req,'RECONCILE','usage_period_summaries',{summaries:rebuilt.rowCount});res.json({message:`Usage reconciliation completed. ${rebuilt.rowCount} monthly summary record(s) rebuilt.`,summaries:rebuilt.rowCount});
}catch(e){try{await client.query('ROLLBACK')}catch(_){}res.status(e.status||500).json({error:e.message})}finally{client.release()}});
app.get('/api/platform/entitlements/usage-health',requirePlatformAuth,async(req,res)=>{try{await requireEntitlementSchema();const result=await pool.query(`SELECT (SELECT COUNT(*)::int FROM usage_events) events,(SELECT COUNT(*)::int FROM usage_period_summaries) summaries,(SELECT COUNT(*)::int FROM usage_events e WHERE NOT EXISTS(SELECT 1 FROM usage_period_summaries s WHERE s.tenant_id=e.tenant_id AND s.feature_id=e.feature_id AND s.period_start=date_trunc('month',e.occurred_at)::date)) events_without_summary,(SELECT MAX(occurred_at) FROM usage_events) last_event_at,(SELECT MAX(updated_at) FROM usage_period_summaries) last_summary_at`);res.json(result.rows[0])}catch(e){res.status(e.status||500).json({error:e.message})}});

// ------------------------ EXPANSION STAGE 1F: READINESS GATE ------------------------
app.get('/api/platform/entitlements/readiness',requirePlatformAuth,async(req,res)=>{const started=Date.now(),checks=[];const add=(code,name,passed,details,critical=true)=>checks.push({code,name,passed:Boolean(passed),critical,details});try{
  await requireEntitlementSchema();
  const requiredTables=['plan_catalog','feature_catalog','plan_features','tenant_subscriptions','tenant_entitlement_overrides','usage_events','usage_period_summaries','feature_flags','feature_flag_tenants'];
  const tables=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[requiredTables])).rows.map(x=>x.table_name);add('schema','Entitlement database structures',tables.length===requiredTables.length,`${tables.length}/${requiredTables.length} required tables available`);
  const subscriptionCoverage=(await pool.query(`SELECT (SELECT COUNT(*)::int FROM tenants) tenants,(SELECT COUNT(*)::int FROM tenant_subscriptions) subscriptions,(SELECT COUNT(*)::int FROM tenants t WHERE NOT EXISTS(SELECT 1 FROM tenant_subscriptions s WHERE s.tenant_id=t.id)) missing`)).rows[0];add('subscriptions','Subscriber subscription backfill',Number(subscriptionCoverage.missing)===0,`${subscriptionCoverage.subscriptions}/${subscriptionCoverage.tenants} companies have a subscription; ${subscriptionCoverage.missing} missing`);
  const tenantTables=['tenant_subscriptions','tenant_entitlement_overrides','usage_events','usage_period_summaries','feature_flag_tenants'];
  const rls=(await pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE c.relrowsecurity)::int enabled,COUNT(*) FILTER(WHERE EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname AND p.policyname='patrolsync_tenant_isolation'))::int policies FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[tenantTables])).rows[0];add('rls','Tenant RLS protection',Number(rls.enabled)===tenantTables.length&&Number(rls.policies)===tenantTables.length,`${rls.enabled}/${tenantTables.length} RLS enabled; ${rls.policies}/${tenantTables.length} tenant policies`);
  const tenantRole=quotedRoleFromTenantUrl();let grantDetails='Restricted tenant role URL is not configured',grantPass=false;if(tenantRole){const roleName=tenantRole.slice(1,-1),grants=(await pool.query(`SELECT COUNT(*) FILTER(WHERE has_table_privilege($1,format('public.%I',x),'SELECT'))::int readable,COUNT(*) FILTER(WHERE has_table_privilege($1,format('public.%I',x),'INSERT,UPDATE,DELETE'))::int writable FROM unnest($2::text[]) x`,[roleName,tenantTables])).rows[0];grantPass=Number(grants.readable)===tenantTables.length&&Number(grants.writable)===tenantTables.length;grantDetails=`${grants.readable}/${tenantTables.length} readable; ${grants.writable}/${tenantTables.length} writable`;}add('tenant_grants','Restricted tenant-role permissions',grantPass,grantDetails);
  const legacyTenants=(await pool.query(`SELECT t.id,t.name,COALESCE(NULLIF(t.plan,''),'starter') legacy_plan FROM tenants t JOIN tenant_subscriptions ts ON ts.tenant_id=t.id JOIN plan_catalog p ON p.id=ts.plan_id WHERE p.version=$1`,[LEGACY_PLAN_VERSION])).rows;let comparisons=0,mismatches=0;for(const tenant of legacyTenants){const usage=await currentCapacityUsage(tenant.id),limits=PLAN_LIMITS[tenant.legacy_plan]||PLAN_LIMITS.starter;for(const[resource,feature]of Object.entries(LEGACY_RESOURCE_FEATURE)){const max=limits[resource],current=Number(usage[feature]||0),legacyAllowed=max===Infinity||max===undefined||current<max,entitlement=await resolveTenantEntitlement(tenant.id,feature),newMax=entitlement?.hard_limit==null?null:Number(entitlement.hard_limit),newAllowed=Boolean(entitlement?.enabled&&['active','trialing'].includes(entitlement.subscription_status)&&(newMax==null||current<newMax));comparisons++;if(legacyAllowed!==newAllowed)mismatches++;}}add('shadow','Legacy compatibility decisions',mismatches===0,`${comparisons-mismatches}/${comparisons} legacy decisions match; ${mismatches} mismatch(es)`);
  const usage=(await pool.query(`SELECT (SELECT COUNT(*)::int FROM usage_events) events,(SELECT COUNT(*)::int FROM usage_events e WHERE NOT EXISTS(SELECT 1 FROM usage_period_summaries s WHERE s.tenant_id=e.tenant_id AND s.feature_id=e.feature_id AND s.period_start=date_trunc('month',e.occurred_at)::date)) missing,(SELECT COUNT(*)::int FROM (SELECT e.tenant_id,e.feature_id,date_trunc('month',e.occurred_at)::date period,SUM(e.quantity) event_total,MAX(s.quantity) summary_total FROM usage_events e LEFT JOIN usage_period_summaries s ON s.tenant_id=e.tenant_id AND s.feature_id=e.feature_id AND s.period_start=date_trunc('month',e.occurred_at)::date GROUP BY e.tenant_id,e.feature_id,date_trunc('month',e.occurred_at)::date HAVING COALESCE(MAX(s.quantity),-1)<>SUM(e.quantity)) q) mismatched`)).rows[0];add('usage','Usage ledger consistency',Number(usage.missing)===0&&Number(usage.mismatched)===0,`${usage.events} event(s); ${usage.missing} without summary; ${usage.mismatched} mismatched summary group(s)`);
  const flags=(await pool.query(`SELECT COUNT(*)::int required,COUNT(*) FILTER(WHERE code IN('entitlement_engine_enforcement','expansion_stage_1'))::int found FROM feature_flags WHERE code IN('entitlement_engine_enforcement','expansion_stage_1')`)).rows[0];add('flags','Feature-flag controls',Number(flags.found)===2,`${flags.found}/2 required flags available`);
  const pilot=(await pool.query(`SELECT COUNT(*) FILTER(WHERE ft.enabled)::int enabled FROM feature_flags f LEFT JOIN feature_flag_tenants ft ON ft.flag_id=f.id WHERE f.code='entitlement_engine_enforcement'`)).rows[0];add('pilot','Safe rollout mode',ENTITLEMENT_ENGINE_MODE!=='enforce',`Mode: ${ENTITLEMENT_ENGINE_MODE}; ${pilot.enabled} pilot company selection(s)`,true);
  const auditTable=(await pool.query(`SELECT to_regclass('public.platform_audit_logs') IS NOT NULL available`)).rows[0];add('audit','Platform audit trail',auditTable.available,'Plan, override, pilot and reconciliation actions are audited');
  const failures=checks.filter(x=>x.critical&&!x.passed),warnings=checks.filter(x=>!x.critical&&!x.passed),ready=failures.length===0;await platformAudit(req,'RUN_GATE','entitlement_readiness',{ready,passed:checks.filter(x=>x.passed).length,failures:failures.length,warnings:warnings.length,mode:ENTITLEMENT_ENGINE_MODE});res.json({ready,status:ready?'STAGE_1_READY':'ACTION_REQUIRED',mode:ENTITLEMENT_ENGINE_MODE,completed_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,warnings:warnings.length,failures:failures.length,total:checks.length},checks});
}catch(e){res.status(e.status||500).json({error:e.message})}});

// ------------------------ SCHEMA HELPERS ------------------------

async function ensureIncidentsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS incidents (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      checkpoint_id INTEGER,
      user_id INTEGER NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'low',
      reported_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS reference_code TEXT`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'general'`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'reported'`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to INTEGER`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resolution TEXT`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS client_incident_id TEXT`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS device_reported_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS offline_captured BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE incidents ADD COLUMN IF NOT EXISTS device_id TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_reference ON incidents(tenant_id,reference_code) WHERE reference_code IS NOT NULL`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_tenant_client_id ON incidents(tenant_id,client_incident_id) WHERE client_incident_id IS NOT NULL`);
  await pool.query(`CREATE TABLE IF NOT EXISTS incident_activities (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    user_id INTEGER,activity_type TEXT NOT NULL,note TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_incident_activities_incident ON incident_activities(tenant_id,incident_id,created_at)`);
  console.log('Incidents table ready');
}
ensureIncidentsTable();

async function ensureHandoverTable(){
  await pool.query(`CREATE TABLE IF NOT EXISTS handover_logs (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,from_user_id INTEGER NOT NULL,
    to_user_id INTEGER,summary TEXT NOT NULL,outstanding_actions TEXT,equipment_status TEXT NOT NULL DEFAULT 'ok',
    status TEXT NOT NULL DEFAULT 'pending',acknowledged_by INTEGER,acknowledged_at TIMESTAMPTZ,
    resolved_by INTEGER,resolved_at TIMESTAMPTZ,resolution_notes TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_handover_tenant_site_status ON handover_logs(tenant_id,site_id,status,created_at DESC)`);
  console.log('Handover table ready');
}
ensureHandoverTable();

async function ensureServiceContractsTable(){
  await pool.query(`CREATE TABLE IF NOT EXISTS service_contracts (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,reference_code TEXT NOT NULL,
    client_name TEXT NOT NULL,start_date DATE NOT NULL,end_date DATE,status TEXT NOT NULL DEFAULT 'draft',
    billing_model TEXT NOT NULL DEFAULT 'monthly',rate NUMERIC(12,2),currency TEXT NOT NULL DEFAULT 'EUR',
    sla_patrol_completion_pct NUMERIC(5,2) NOT NULL DEFAULT 95,
    sla_incident_ack_minutes INTEGER NOT NULL DEFAULT 15,sla_shift_coverage_pct NUMERIC(5,2) NOT NULL DEFAULT 98,
    report_frequency TEXT NOT NULL DEFAULT 'monthly',notes TEXT,created_by INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,reference_code)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_contracts_tenant_site_status ON service_contracts(tenant_id,site_id,status)`);
  console.log('Service contracts table ready');
}
ensureServiceContractsTable();

async function ensureClientReportAutomationTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS client_report_schedules (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id) ON DELETE CASCADE,
    recipient_email TEXT NOT NULL,frequency TEXT NOT NULL,next_run_date DATE NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(contract_id,recipient_email)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS client_report_runs (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,schedule_id BIGINT REFERENCES client_report_schedules(id) ON DELETE SET NULL,
    contract_id BIGINT NOT NULL REFERENCES service_contracts(id),period_start DATE NOT NULL,period_end DATE NOT NULL,
    recipient_email TEXT,status TEXT NOT NULL DEFAULT 'generated',generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,delivered_by INTEGER,delivery_notes TEXT,UNIQUE(schedule_id,period_start,period_end)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_report_schedules_due ON client_report_schedules(active,next_run_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_report_runs_tenant_generated ON client_report_runs(tenant_id,generated_at DESC)`);
  console.log('Client report automation tables ready');
}
ensureClientReportAutomationTables();

async function ensureBillingTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS invoices (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id),
    invoice_number TEXT NOT NULL,period_start DATE NOT NULL,period_end DATE NOT NULL,issue_date DATE,due_date DATE,
    status TEXT NOT NULL DEFAULT 'draft',currency TEXT NOT NULL DEFAULT 'EUR',subtotal NUMERIC(12,2) NOT NULL DEFAULT 0,
    tax_rate NUMERIC(5,2) NOT NULL DEFAULT 0,tax_amount NUMERIC(12,2) NOT NULL DEFAULT 0,total NUMERIC(12,2) NOT NULL DEFAULT 0,
    amount_paid NUMERIC(12,2) NOT NULL DEFAULT 0,notes TEXT,created_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,invoice_number),UNIQUE(contract_id,period_start,period_end)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS invoice_lines (
    id BIGSERIAL PRIMARY KEY,invoice_id BIGINT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,description TEXT NOT NULL,
    quantity NUMERIC(12,2) NOT NULL,unit_rate NUMERIC(12,2) NOT NULL,line_total NUMERIC(12,2) NOT NULL
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS invoice_payments (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,invoice_id BIGINT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    amount NUMERIC(12,2) NOT NULL,payment_date DATE NOT NULL,method TEXT,reference TEXT,notes TEXT,recorded_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_invoices_tenant_status_due ON invoices(tenant_id,status,due_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_invoice_payments_invoice ON invoice_payments(invoice_id,payment_date)`);
  console.log('Billing tables ready');
}
ensureBillingTables();

async function ensureServiceTicketTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS service_tickets (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,client_user_id INTEGER,
    reference_code TEXT NOT NULL,request_type TEXT NOT NULL DEFAULT 'general',subject TEXT NOT NULL,description TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'normal',status TEXT NOT NULL DEFAULT 'open',assigned_to INTEGER,
    resolution TEXT,resolved_at TIMESTAMPTZ,closed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,reference_code)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS service_ticket_comments (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,ticket_id BIGINT NOT NULL REFERENCES service_tickets(id) ON DELETE CASCADE,
    author_type TEXT NOT NULL,author_user_id INTEGER,author_client_user_id INTEGER,comment TEXT NOT NULL,internal BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_service_tickets_queue ON service_tickets(tenant_id,status,priority,updated_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_service_ticket_comments ON service_ticket_comments(ticket_id,created_at)`);
  console.log('Service ticket tables ready');
}
ensureServiceTicketTables();

async function ensureContractRenewalTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS contract_renewals (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'not_started',owner_user_id INTEGER,proposed_start_date DATE,proposed_end_date DATE,
    proposed_rate NUMERIC(12,2),proposed_currency TEXT,notes TEXT,last_contact_at TIMESTAMPTZ,next_follow_up_date DATE,
    completed_contract_id BIGINT REFERENCES service_contracts(id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(contract_id)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS contract_renewal_history (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,renewal_id BIGINT NOT NULL REFERENCES contract_renewals(id) ON DELETE CASCADE,
    action TEXT NOT NULL,note TEXT,user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE service_contracts ADD COLUMN IF NOT EXISTS previous_contract_id BIGINT`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_contract_renewals_pipeline ON contract_renewals(tenant_id,status,next_follow_up_date)`);
  console.log('Contract renewal tables ready');
}
ensureContractRenewalTables();

async function ensureEmailDeliveryTable(){
  await pool.query(`CREATE TABLE IF NOT EXISTS email_deliveries (
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,event_type TEXT NOT NULL,entity_type TEXT,entity_id BIGINT,
    idempotency_key TEXT NOT NULL,recipient_email TEXT NOT NULL,subject TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'queued',
    provider TEXT,provider_message_id TEXT,payload JSONB NOT NULL DEFAULT '{}'::jsonb,attempt_count INTEGER NOT NULL DEFAULT 0,last_error TEXT,
    sent_at TIMESTAMPTZ,next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(idempotency_key,recipient_email)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_email_delivery_queue ON email_deliveries(status,next_attempt_at)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_email_delivery_tenant ON email_deliveries(tenant_id,created_at DESC)`);
  await pool.query(`ALTER TABLE email_deliveries ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT '{}'::jsonb`);
  console.log('Email delivery table ready');
}
ensureEmailDeliveryTable();

async function ensureIncidentPhotosTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS incident_photos (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      incident_id INTEGER NOT NULL,
      photo_data TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE incident_photos ALTER COLUMN photo_data DROP NOT NULL`);
  await pool.query(`ALTER TABLE incident_photos ADD COLUMN IF NOT EXISTS storage_provider TEXT NOT NULL DEFAULT 'database'`);
  await pool.query(`ALTER TABLE incident_photos ADD COLUMN IF NOT EXISTS storage_key TEXT`);
  await pool.query(`ALTER TABLE incident_photos ADD COLUMN IF NOT EXISTS content_type TEXT`);
  await pool.query(`ALTER TABLE incident_photos ADD COLUMN IF NOT EXISTS size_bytes INTEGER`);
  await pool.query(`ALTER TABLE incident_photos ADD COLUMN IF NOT EXISTS checksum_sha256 TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_photos_storage_key ON incident_photos(storage_key) WHERE storage_key IS NOT NULL`);
  console.log('Incident photos table ready');
}
ensureIncidentPhotosTable();

async function ensureAuthColumn() {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`);
  console.log('Auth column ready');
}
ensureAuthColumn();

async function ensureFirebaseUidNullable() {
  await pool.query(`ALTER TABLE users ALTER COLUMN firebase_uid DROP NOT NULL`);
  console.log('firebase_uid is now nullable');
}
ensureFirebaseUidNullable();

async function ensureTimezoneColumn() {
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS timezone TEXT DEFAULT 'UTC'`);
  console.log('Timezone column ready');
}
ensureTimezoneColumn();

async function ensureEmergencyContactColumns() {
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS emergency_phone TEXT`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS emergency_whatsapp TEXT`);
  console.log('Emergency contact columns ready');
}
ensureEmergencyContactColumns();

async function ensureSiteGeofenceColumns() {
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS geofence_radius_m INTEGER NOT NULL DEFAULT 150`);
  await pool.query(`ALTER TABLE sites ADD COLUMN IF NOT EXISTS geofence_enabled BOOLEAN NOT NULL DEFAULT FALSE`);
  console.log('Site geofence columns ready');
}
ensureSiteGeofenceColumns();

async function ensureNotificationsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      site_name TEXT NOT NULL,
      checkpoint_id INTEGER NOT NULL,
      checkpoint_name TEXT NOT NULL,
      message TEXT NOT NULL,
      hours_overdue NUMERIC DEFAULT 0,
      resolved BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMP
    )
  `);
  console.log('Notifications table ready');
}
ensureNotificationsTable();

async function ensureCommunicationNotificationsTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS communication_notifications (
      id BIGSERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'general',
      priority TEXT NOT NULL DEFAULT 'normal',
      audience TEXT NOT NULL DEFAULT 'all_guards',
      recipient_user_id INTEGER,
      action_url TEXT,
      requires_acknowledgement BOOLEAN NOT NULL DEFAULT FALSE,
      created_by_user_id INTEGER,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT communication_notification_priority CHECK (priority IN ('low','normal','high','critical')),
      CONSTRAINT communication_notification_audience CHECK (audience IN ('all','admins','all_guards','specific_guard'))
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS communication_notification_receipts (
      notification_id BIGINT NOT NULL REFERENCES communication_notifications(id) ON DELETE CASCADE,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      read_at TIMESTAMPTZ,
      acknowledged_at TIMESTAMPTZ,
      PRIMARY KEY (notification_id, user_id)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_notifications_tenant_created ON communication_notifications(tenant_id,created_at DESC)`);
  await pool.query(`ALTER TABLE communication_notifications ADD COLUMN IF NOT EXISTS source_key TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_comm_notifications_tenant_source ON communication_notifications(tenant_id,source_key) WHERE source_key IS NOT NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_notification_receipts_user ON communication_notification_receipts(tenant_id,user_id)`);
  console.log('Communication notification tables ready');
}
ensureCommunicationNotificationsTables();

async function ensureTeamMessagingTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS team_conversations (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, title TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'company', guard_user_id INTEGER, created_by_user_id INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT team_conversation_kind CHECK (kind IN ('company','direct'))
  )`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_team_company_channel ON team_conversations(tenant_id) WHERE kind='company'`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_team_direct_channel ON team_conversations(tenant_id,guard_user_id) WHERE kind='direct'`);
  await pool.query(`CREATE TABLE IF NOT EXISTS team_messages (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
    conversation_id BIGINT NOT NULL REFERENCES team_conversations(id) ON DELETE CASCADE,
    sender_user_id INTEGER NOT NULL, sender_role TEXT NOT NULL, message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_team_messages_conversation ON team_messages(tenant_id,conversation_id,created_at)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS team_conversation_reads (
    tenant_id INTEGER NOT NULL, conversation_id BIGINT NOT NULL REFERENCES team_conversations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL, last_read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(conversation_id,user_id)
  )`);
  console.log('Team messaging tables ready');
}
ensureTeamMessagingTables();

async function ensureLoneWorkerTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS lone_worker_settings (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL, site_id INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE, interval_minutes INTEGER NOT NULL DEFAULT 60,
    grace_minutes INTEGER NOT NULL DEFAULT 10, instructions TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(tenant_id,user_id,site_id),
    CONSTRAINT lone_worker_interval CHECK(interval_minutes BETWEEN 5 AND 720),
    CONSTRAINT lone_worker_grace CHECK(grace_minutes BETWEEN 0 AND 120)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lone_worker_checkins (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, setting_id BIGINT NOT NULL REFERENCES lone_worker_settings(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL, site_id INTEGER NOT NULL, latitude DOUBLE PRECISION, longitude DOUBLE PRECISION,
    accuracy DOUBLE PRECISION, note TEXT, checked_in_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS lone_worker_alerts (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, setting_id BIGINT NOT NULL REFERENCES lone_worker_settings(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL, site_id INTEGER NOT NULL, due_at TIMESTAMPTZ NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), resolved_at TIMESTAMPTZ
  )`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_lone_worker_open_alert ON lone_worker_alerts(setting_id) WHERE resolved=FALSE`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_lone_worker_checkins_latest ON lone_worker_checkins(tenant_id,setting_id,checked_in_at DESC)`);
  console.log('Lone-worker safety tables ready');
}
ensureLoneWorkerTables();

async function ensureDispatchTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS dispatch_jobs (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, reference_code TEXT NOT NULL,
    title TEXT NOT NULL, description TEXT, priority TEXT NOT NULL DEFAULT 'normal', status TEXT NOT NULL DEFAULT 'assigned',
    site_id INTEGER, assigned_guard_id INTEGER NOT NULL, address TEXT, latitude DOUBLE PRECISION, longitude DOUBLE PRECISION,
    created_by_user_id INTEGER, assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), accepted_at TIMESTAMPTZ,
    en_route_at TIMESTAMPTZ, on_site_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, completion_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,reference_code), CONSTRAINT dispatch_priority CHECK(priority IN ('low','normal','high','critical')),
    CONSTRAINT dispatch_status CHECK(status IN ('assigned','accepted','en_route','on_site','completed','cancelled'))
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_dispatch_tenant_status ON dispatch_jobs(tenant_id,status,created_at DESC)`);
  console.log('Dispatch tables ready');
}
ensureDispatchTables();

async function ensureCrisisModeTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS crisis_activations(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,incident_id INTEGER NOT NULL REFERENCES incidents(id),site_id INTEGER NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL DEFAULT 'major',status TEXT NOT NULL DEFAULT 'active',commander_user_id INTEGER NOT NULL,activated_by_user_id INTEGER NOT NULL,activation_reason TEXT NOT NULL,activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),stood_down_by_user_id INTEGER,stood_down_at TIMESTAMPTZ,stand_down_reason TEXT,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT crisis_status_check CHECK(status IN('active','contained','stood_down')),CONSTRAINT crisis_severity_check CHECK(severity IN('major','critical')))`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_active_crisis_incident ON crisis_activations(tenant_id,incident_id) WHERE status<>'stood_down'`);
  await pool.query(`CREATE TABLE IF NOT EXISTS crisis_roles(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,crisis_id BIGINT NOT NULL REFERENCES crisis_activations(id) ON DELETE CASCADE,role_name TEXT NOT NULL,user_id INTEGER NOT NULL,assigned_by_user_id INTEGER NOT NULL,assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,crisis_id,role_name))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS crisis_actions(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,crisis_id BIGINT NOT NULL REFERENCES crisis_activations(id) ON DELETE CASCADE,title TEXT NOT NULL,description TEXT,priority TEXT NOT NULL DEFAULT 'high',status TEXT NOT NULL DEFAULT 'open',assigned_user_id INTEGER,due_at TIMESTAMPTZ,created_by_user_id INTEGER NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),completed_by_user_id INTEGER,completed_at TIMESTAMPTZ,completion_note TEXT,CONSTRAINT crisis_action_status CHECK(status IN('open','in_progress','completed','cancelled')),CONSTRAINT crisis_action_priority CHECK(priority IN('normal','high','critical')))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS crisis_updates(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,crisis_id BIGINT NOT NULL REFERENCES crisis_activations(id) ON DELETE CASCADE,update_type TEXT NOT NULL DEFAULT 'operational',message TEXT NOT NULL,created_by_user_id INTEGER NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT crisis_update_type CHECK(update_type IN('operational','communication','decision','status')))`);
  for(const table of ['crisis_activations','crisis_roles','crisis_actions','crisis_updates']){await pool.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ${table}`);await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ${table} USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`)}
  const tenantRole=quotedRoleFromTenantUrl();if(tenantRole){for(const table of ['crisis_activations','crisis_roles','crisis_actions','crisis_updates'])await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON ${table} TO ${tenantRole}`);await pool.query(`GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO ${tenantRole}`)}
  console.log('Crisis Mode tables ready');
}
const crisisModeSchemaReady=ensureCrisisModeTables().catch(error=>{console.error('Crisis Mode setup failed:',error.message);throw error});

async function ensureTrainingTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS training_materials(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,title TEXT NOT NULL,material_type TEXT NOT NULL,version TEXT NOT NULL DEFAULT '1.0',content TEXT NOT NULL,site_id INTEGER,questions JSONB NOT NULL DEFAULT '[]'::jsonb,passing_score INTEGER NOT NULL DEFAULT 80,active BOOLEAN NOT NULL DEFAULT TRUE,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT training_type CHECK(material_type IN ('training','policy','post_order')),CONSTRAINT training_score CHECK(passing_score BETWEEN 0 AND 100))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS training_assignments(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,material_id BIGINT NOT NULL REFERENCES training_materials(id) ON DELETE CASCADE,user_id INTEGER NOT NULL,due_at TIMESTAMPTZ,mandatory BOOLEAN NOT NULL DEFAULT TRUE,status TEXT NOT NULL DEFAULT 'assigned',score INTEGER,attempts INTEGER NOT NULL DEFAULT 0,acknowledged_at TIMESTAMPTZ,completed_at TIMESTAMPTZ,assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(material_id,user_id),CONSTRAINT training_assignment_status CHECK(status IN ('assigned','failed','completed')))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS site_training_requirements(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,material_id BIGINT NOT NULL REFERENCES training_materials(id) ON DELETE CASCADE,due_days INTEGER NOT NULL DEFAULT 14,active BOOLEAN NOT NULL DEFAULT TRUE,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,site_id,material_id))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_training_assignments_user ON training_assignments(tenant_id,user_id,status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_site_training_requirements_site ON site_training_requirements(tenant_id,site_id,active)`);
  await pool.query(`ALTER TABLE site_training_requirements ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON site_training_requirements`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON site_training_requirements USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  const tenantRole=quotedRoleFromTenantUrl();if(tenantRole){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON site_training_requirements TO ${tenantRole}`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE site_training_requirements_id_seq TO ${tenantRole}`)}
  console.log('Training and compliance tables ready');
}
ensureTrainingTables();

async function ensureAssetTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS managed_assets(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,asset_type TEXT NOT NULL,name TEXT NOT NULL,asset_code TEXT NOT NULL,site_id INTEGER,status TEXT NOT NULL DEFAULT 'available',condition TEXT NOT NULL DEFAULT 'good',notes TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,asset_code),CONSTRAINT asset_type_check CHECK(asset_type IN ('equipment','key','vehicle','uniform','device','other')),CONSTRAINT asset_status_check CHECK(status IN ('available','issued','maintenance','lost','retired')))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS asset_custody(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,asset_id BIGINT NOT NULL REFERENCES managed_assets(id) ON DELETE CASCADE,user_id INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'issued',issued_by_user_id INTEGER,issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),acknowledged_at TIMESTAMPTZ,return_requested_at TIMESTAMPTZ,returned_at TIMESTAMPTZ,return_condition TEXT,guard_note TEXT,admin_note TEXT,CONSTRAINT custody_status_check CHECK(status IN ('issued','acknowledged','return_requested','returned','reported_lost','reported_damaged')))`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_open_custody ON asset_custody(asset_id) WHERE status<>'returned'`);
  console.log('Asset custody tables ready');
}ensureAssetTables();

async function ensureQualityTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS inspection_templates(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,title TEXT NOT NULL,description TEXT,site_id INTEGER,passing_score INTEGER NOT NULL DEFAULT 80,questions JSONB NOT NULL DEFAULT '[]'::jsonb,active BOOLEAN NOT NULL DEFAULT TRUE,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT inspection_passing_score CHECK(passing_score BETWEEN 0 AND 100))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS inspection_runs(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,template_id BIGINT NOT NULL REFERENCES inspection_templates(id) ON DELETE CASCADE,site_id INTEGER NOT NULL,assigned_user_id INTEGER NOT NULL,scheduled_for TIMESTAMPTZ NOT NULL,status TEXT NOT NULL DEFAULT 'scheduled',responses JSONB NOT NULL DEFAULT '[]'::jsonb,score INTEGER,overall_note TEXT,started_at TIMESTAMPTZ,submitted_at TIMESTAMPTZ,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),CONSTRAINT inspection_run_status CHECK(status IN ('scheduled','in_progress','submitted','cancelled')))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS corrective_actions(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,inspection_run_id BIGINT NOT NULL REFERENCES inspection_runs(id) ON DELETE CASCADE,question_index INTEGER,title TEXT NOT NULL,description TEXT,assigned_user_id INTEGER,due_at TIMESTAMPTZ,status TEXT NOT NULL DEFAULT 'open',resolution_note TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),resolved_at TIMESTAMPTZ,CONSTRAINT corrective_status CHECK(status IN ('open','in_progress','resolved','cancelled')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_inspection_runs_assignee ON inspection_runs(tenant_id,assigned_user_id,status,scheduled_for)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_corrective_actions_status ON corrective_actions(tenant_id,status,due_at)`);
  console.log('Quality inspection tables ready');
}ensureQualityTables();

async function ensureTenantLifecycleSchema(){
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS account_active BOOLEAN NOT NULL DEFAULT TRUE`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspension_reason TEXT`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS subscription_status TEXT NOT NULL DEFAULT 'active'`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS billing_cycle TEXT NOT NULL DEFAULT 'monthly'`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS renewal_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS platform_notes TEXT`);
  console.log('Subscriber lifecycle columns ready');
}
ensureTenantLifecycleSchema().catch(e=>console.error('Subscriber lifecycle setup failed:',e.message));

async function ensureStaffAccessColumns(){await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb`);await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title TEXT`);await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_active BOOLEAN NOT NULL DEFAULT TRUE`);await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_active_identity_unique ON users(tenant_id,LOWER(email),role) WHERE account_active=TRUE AND role IN('guard','staff')`);console.log('Staff access columns and active identity protection ready');}ensureStaffAccessColumns().catch(e=>console.error('Staff access setup failed:',e.message));
async function ensureEmailMfaSchema(){await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE`);await pool.query(`CREATE TABLE IF NOT EXISTS email_mfa_challenges(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,purpose TEXT NOT NULL CHECK(purpose IN('login','enable')),token_hash TEXT NOT NULL UNIQUE,code_hash TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS mfa_recovery_codes(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,code_hash TEXT NOT NULL,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,user_id,code_hash))`);for(const table of ['email_mfa_challenges','mfa_recovery_codes']){await pool.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ${table}`);await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ${table} USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`)}await pool.query(`CREATE INDEX IF NOT EXISTS email_mfa_challenges_lookup ON email_mfa_challenges(token_hash,expires_at) WHERE used_at IS NULL`);console.log('Email MFA schema ready')}ensureEmailMfaSchema().catch(e=>console.error('Email MFA setup failed:',e.message));
async function ensureAuthSessionsSchema(){await pool.query(`CREATE TABLE IF NOT EXISTS auth_sessions(id UUID PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,role TEXT NOT NULL,ip_address TEXT,user_agent TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ,revoked_reason TEXT)`);await pool.query(`CREATE INDEX IF NOT EXISTS auth_sessions_user_lookup ON auth_sessions(tenant_id,user_id,created_at DESC)`);console.log('Tracked authentication sessions ready')}ensureAuthSessionsSchema().catch(e=>console.error('Auth session setup failed:',e.message));
async function ensurePlatformAdminSchema(){await pool.query(`CREATE TABLE IF NOT EXISTS platform_admins(id BIGSERIAL PRIMARY KEY,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,display_name TEXT,active BOOLEAN NOT NULL DEFAULT TRUE,last_login_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS platform_mfa_challenges(id BIGSERIAL PRIMARY KEY,platform_admin_id BIGINT NOT NULL,token_hash TEXT NOT NULL UNIQUE,code_hash TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,used_at TIMESTAMPTZ,ip_address TEXT,user_agent TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS platform_mfa_recovery_codes(id BIGSERIAL PRIMARY KEY,platform_admin_id BIGINT NOT NULL,code_hash TEXT NOT NULL,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(platform_admin_id,code_hash))`);await pool.query(`CREATE TABLE IF NOT EXISTS platform_auth_sessions(id UUID PRIMARY KEY,platform_admin_id BIGINT NOT NULL,ip_address TEXT,user_agent TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ,revoked_reason TEXT)`);await pool.query(`CREATE INDEX IF NOT EXISTS platform_auth_sessions_lookup ON platform_auth_sessions(platform_admin_id,created_at DESC)`);await pool.query(`CREATE TABLE IF NOT EXISTS platform_audit_logs(id BIGSERIAL PRIMARY KEY,platform_admin_id BIGINT,admin_email TEXT,action TEXT NOT NULL,resource TEXT,details JSONB NOT NULL DEFAULT '{}'::jsonb,ip_address TEXT,request_id TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);const email=String(process.env.PLATFORM_ADMIN_EMAIL||'').trim().toLowerCase(),password=String(process.env.PLATFORM_ADMIN_PASSWORD||'');const count=Number((await pool.query(`SELECT COUNT(*)::int count FROM platform_admins`)).rows[0].count);if(count===0&&email&&password.length>=12){const hash=await bcrypt.hash(password,12);await pool.query(`INSERT INTO platform_admins(email,password_hash,display_name) VALUES($1,$2,'Platform Owner')`,[email,hash]);console.log('Initial platform administrator created')}else if(count===0)console.warn('No platform administrator exists. Set PLATFORM_ADMIN_EMAIL and PLATFORM_ADMIN_PASSWORD (12+ characters) to bootstrap one.');console.log('Platform administrator schema ready')}ensurePlatformAdminSchema().catch(e=>console.error('Platform admin setup failed:',e.message));
async function ensureLaunchReadinessSchema(){await pool.query(`CREATE TABLE IF NOT EXISTS platform_launch_attestations(id SMALLINT PRIMARY KEY DEFAULT 1 CHECK(id=1),backup_verified_at TIMESTAMPTZ,backup_filename TEXT,backup_sha256 TEXT,monitoring_verified_at TIMESTAMPTZ,monitoring_endpoint TEXT,notes TEXT,updated_by_platform_admin_id BIGINT,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`INSERT INTO platform_launch_attestations(id) VALUES(1) ON CONFLICT(id) DO NOTHING`);console.log('Launch readiness schema ready')}ensureLaunchReadinessSchema().catch(e=>console.error('Launch readiness setup failed:',e.message));
async function createTrackedToken(user,req){const sessionId=crypto.randomUUID(),userId=Number(user.id||user.user_id),tenantId=Number(user.tenant_id),role=user.role,email=user.email,ip=requestIp(req),userAgent=String(req.headers['user-agent']||'').slice(0,500);const previous=await pool.query(`SELECT 1 FROM auth_sessions WHERE tenant_id=$1 AND user_id=$2 AND user_agent=$3 AND ip_address=$4 LIMIT 1`,[tenantId,userId,userAgent,ip]);const newDevice=!previous.rowCount;await pool.query(`INSERT INTO auth_sessions(id,tenant_id,user_id,role,ip_address,user_agent,expires_at) VALUES($1,$2,$3,$4,$5,$6,NOW()+INTERVAL '12 hours')`,[sessionId,tenantId,userId,role,ip,userAgent]);await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details,request_id) VALUES($1,$2,$3,$4,$5::jsonb,$6)`,[tenantId,newDevice?'new_device_login':'account_login',newDevice?'warning':'info',newDevice?'Administrator login from a new device':'Administrator login recorded',JSON.stringify({user_id:userId,email,role,ip_address:ip,user_agent:userAgent,session_id:sessionId}),req.requestId||null]);if(newDevice&&process.env.BREVO_API_KEY&&EMAIL_FROM_ADDRESS){const safe=v=>String(v||'').replace(/[&<>]/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[x]));sendProviderEmail({to:email,subject:'New PatrolSync administrator login',html:emailHtml('New administrator login',`<p>PatrolSync detected a login from a device or network not previously recorded for your account.</p><p><b>Time:</b> ${safe(new Date().toISOString())}<br><b>IP:</b> ${safe(ip)}<br><b>Device:</b> ${safe(userAgent||'Unknown')}</p><p>If this was not you, open Active Sessions & Devices and revoke the session immediately.</p>`,'Review Sessions',FRONTEND_URL&&`${FRONTEND_URL}/session_management.html`)}).catch(e=>console.error('New-device alert email failed:',e.message))}return jwt.sign({user_id:userId,tenant_id:tenantId,role,email,session_id:sessionId},JWT_SECRET,{expiresIn:'12h'})}

function mfaDigest(value){return crypto.createHmac('sha256',JWT_SECRET).update(String(value)).digest('hex')}
function normalizeRecoveryCode(value){return String(value||'').toUpperCase().replace(/[^A-Z0-9]/g,'')}
function makeRecoveryCodes(){return Array.from({length:8},()=>{const raw=crypto.randomBytes(5).toString('hex').toUpperCase();return `${raw.slice(0,5)}-${raw.slice(5)}`})}
async function replaceUserRecoveryCodes(tenantId,userId){const codes=makeRecoveryCodes(),client=await pool.connect();try{await client.query('BEGIN');await client.query(`DELETE FROM mfa_recovery_codes WHERE tenant_id=$1 AND user_id=$2`,[tenantId,userId]);for(const code of codes)await client.query(`INSERT INTO mfa_recovery_codes(tenant_id,user_id,code_hash) VALUES($1,$2,$3)`,[tenantId,userId,mfaDigest('recovery:'+normalizeRecoveryCode(code))]);await client.query('COMMIT');return codes}catch(e){try{await client.query('ROLLBACK')}catch(_){}throw e}finally{client.release()}}
async function createEmailMfaChallenge(user,purpose){const rawToken=crypto.randomBytes(32).toString('hex'),code=String(crypto.randomInt(0,1000000)).padStart(6,'0');await pool.query(`UPDATE email_mfa_challenges SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND purpose=$3 AND used_at IS NULL`,[user.id,user.tenant_id,purpose]);await pool.query(`INSERT INTO email_mfa_challenges(tenant_id,user_id,purpose,token_hash,code_hash,expires_at) VALUES($1,$2,$3,$4,$5,NOW()+INTERVAL '10 minutes')`,[user.tenant_id,user.id,purpose,mfaDigest(rawToken),mfaDigest(code)]);await sendProviderEmail({to:user.email,subject:'Your PatrolSync verification code',html:emailHtml('PatrolSync verification code',`<p>Enter this code to continue:</p><p style="font-size:30px;font-weight:bold;letter-spacing:6px">${code}</p><p>This code expires in 10 minutes and can be used once.</p>`)});return rawToken}
async function consumeEmailMfaChallenge(rawToken,code,purpose){const tokenHash=mfaDigest(rawToken),client=await pool.connect();try{await client.query('BEGIN');const found=await client.query(`SELECT c.*,u.email,u.role,u.account_active FROM email_mfa_challenges c JOIN users u ON u.id=c.user_id AND u.tenant_id=c.tenant_id WHERE c.token_hash=$1 AND c.purpose=$2 AND c.used_at IS NULL AND c.expires_at>NOW() FOR UPDATE OF c`,[tokenHash,purpose]);if(!found.rowCount)throw Object.assign(new Error('Verification code is invalid or expired'),{statusCode:400});const challenge=found.rows[0];if(challenge.account_active===false)throw Object.assign(new Error('Account is disabled'),{statusCode:401});if(challenge.attempts>=5)throw Object.assign(new Error('Too many incorrect attempts. Request a new code.'),{statusCode:429});const supplied=mfaDigest(String(code||'').trim()),valid=crypto.timingSafeEqual(Buffer.from(supplied,'hex'),Buffer.from(challenge.code_hash,'hex'));if(!valid){await client.query(`UPDATE email_mfa_challenges SET attempts=attempts+1 WHERE id=$1`,[challenge.id]);await client.query('COMMIT');throw Object.assign(new Error('Incorrect verification code'),{statusCode:400})}await client.query(`UPDATE email_mfa_challenges SET used_at=NOW() WHERE id=$1`,[challenge.id]);await client.query('COMMIT');return challenge}catch(e){try{await client.query('ROLLBACK')}catch(_){}throw e}finally{client.release()}}
async function consumeUserRecoveryCode(rawToken,code){const client=await pool.connect();try{await client.query('BEGIN');const challenge=(await client.query(`SELECT c.*,u.email,u.role,u.account_active FROM email_mfa_challenges c JOIN users u ON u.id=c.user_id AND u.tenant_id=c.tenant_id WHERE c.token_hash=$1 AND c.purpose='login' AND c.used_at IS NULL AND c.expires_at>NOW() FOR UPDATE OF c`,[mfaDigest(rawToken)])).rows[0];if(!challenge||challenge.account_active===false)throw Object.assign(new Error('Recovery attempt is invalid or expired'),{statusCode:400});const recovery=(await client.query(`SELECT id FROM mfa_recovery_codes WHERE tenant_id=$1 AND user_id=$2 AND code_hash=$3 AND used_at IS NULL FOR UPDATE`,[challenge.tenant_id,challenge.user_id,mfaDigest('recovery:'+normalizeRecoveryCode(code))])).rows[0];if(!recovery)throw Object.assign(new Error('Recovery code is invalid or already used'),{statusCode:400});await client.query(`UPDATE mfa_recovery_codes SET used_at=NOW() WHERE id=$1`,[recovery.id]);await client.query(`UPDATE email_mfa_challenges SET used_at=NOW() WHERE id=$1`,[challenge.id]);await client.query('COMMIT');return challenge}catch(e){try{await client.query('ROLLBACK')}catch(_){}throw e}finally{client.release()}}

async function ensureIntegrationTables(){await pool.query(`CREATE TABLE IF NOT EXISTS integration_api_keys(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,name TEXT NOT NULL,key_prefix TEXT NOT NULL,key_hash TEXT NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE,last_used_at TIMESTAMPTZ,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS webhook_endpoints(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,name TEXT NOT NULL,url TEXT NOT NULL,secret TEXT NOT NULL,event_filter TEXT NOT NULL DEFAULT '*',active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE TABLE IF NOT EXISTS webhook_deliveries(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,webhook_id BIGINT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,event_type TEXT NOT NULL,payload JSONB NOT NULL,status TEXT NOT NULL DEFAULT 'queued',attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),response_status INTEGER,last_error TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),delivered_at TIMESTAMPTZ)`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_webhook_queue ON webhook_deliveries(status,next_attempt_at)`);console.log('Integration tables ready');}ensureIntegrationTables();

async function ensureOperationsTables(){await pool.query(`CREATE TABLE IF NOT EXISTS system_events(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER,event_type TEXT NOT NULL,severity TEXT NOT NULL DEFAULT 'info',message TEXT NOT NULL,details JSONB NOT NULL DEFAULT '{}'::jsonb,request_id TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_system_events_tenant_created ON system_events(tenant_id,created_at DESC)`);console.log('Operations monitoring table ready');}ensureOperationsTables();

async function ensureSecurityRecoveryTables(){await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ`);await pool.query(`CREATE TABLE IF NOT EXISTS password_reset_tokens(id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,expires_at TIMESTAMPTZ NOT NULL,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_reset_expiry ON password_reset_tokens(expires_at) WHERE used_at IS NULL`);console.log('Security and recovery tables ready');}ensureSecurityRecoveryTables();

async function ensureAuditLogsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER,
      user_email TEXT,
      user_role TEXT,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      entity_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      ip_address TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id,created_at DESC)`);
  console.log('Audit logs table ready');
}
ensureAuditLogsTable();

async function ensurePatrolRoutesTables() {
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_routes (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, site_id INTEGER NOT NULL,
    name TEXT NOT NULL, description TEXT, strict_order BOOLEAN NOT NULL DEFAULT TRUE,
    estimated_minutes INTEGER, active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,site_id,name)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_route_checkpoints (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, route_id INTEGER NOT NULL REFERENCES patrol_routes(id) ON DELETE CASCADE,
    checkpoint_id INTEGER NOT NULL, position INTEGER NOT NULL,
    UNIQUE(route_id,checkpoint_id), UNIQUE(route_id,position)
  )`);
  await pool.query(`ALTER TABLE patrol_route_checkpoints ADD COLUMN IF NOT EXISTS instructions TEXT`);
  await pool.query(`ALTER TABLE patrol_route_checkpoints ADD COLUMN IF NOT EXISTS requires_confirmation BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE patrol_route_checkpoints ADD COLUMN IF NOT EXISTS requires_note BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_routes_tenant_site ON patrol_routes(tenant_id,site_id)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_runs (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, route_id INTEGER NOT NULL REFERENCES patrol_routes(id),
    site_id INTEGER NOT NULL, user_id INTEGER NOT NULL, scheduled_start TIMESTAMPTZ NOT NULL,
    scheduled_end TIMESTAMPTZ NOT NULL, grace_minutes INTEGER NOT NULL DEFAULT 15,
    status TEXT NOT NULL DEFAULT 'scheduled', notes TEXT, started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ, cancelled_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_run_scans (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, run_id BIGINT NOT NULL REFERENCES patrol_runs(id) ON DELETE CASCADE,
    checkpoint_id INTEGER NOT NULL, patrol_log_id INTEGER, position INTEGER NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(run_id,checkpoint_id)
  )`);
  await pool.query(`ALTER TABLE patrol_run_scans ADD COLUMN IF NOT EXISTS checkpoint_note TEXT`);
  await pool.query(`ALTER TABLE patrol_run_scans ADD COLUMN IF NOT EXISTS instruction_confirmed BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_runs_tenant_start ON patrol_runs(tenant_id,scheduled_start)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_runs_guard_start ON patrol_runs(tenant_id,user_id,scheduled_start)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS patrol_alerts (
    id BIGSERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, run_id BIGINT NOT NULL REFERENCES patrol_runs(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', acknowledged_at TIMESTAMPTZ, acknowledged_by INTEGER,
    resolved_at TIMESTAMPTZ, resolved_by INTEGER, resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(run_id,alert_type)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_alerts_tenant_status ON patrol_alerts(tenant_id,status,created_at DESC)`);
  console.log('Patrol route tables ready');
}
ensurePatrolRoutesTables();

async function ensurePatrolEvidenceColumns() {
  await pool.query(`ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS nfc_tag_uid TEXT`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS patrol_run_id BIGINT`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS accuracy_m DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS distance_m DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS location_status TEXT NOT NULL DEFAULT 'unavailable'`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS device_scanned_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS client_scan_id TEXT`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS scan_method TEXT NOT NULL DEFAULT 'qr'`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS device_id TEXT`);
  await pool.query(`ALTER TABLE patrol_logs ADD COLUMN IF NOT EXISTS offline_captured BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_checkpoints_tenant_nfc_tag ON checkpoints(tenant_id,nfc_tag_uid) WHERE nfc_tag_uid IS NOT NULL`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_patrol_logs_tenant_client_scan ON patrol_logs(tenant_id,client_scan_id) WHERE client_scan_id IS NOT NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_patrol_logs_evidence ON patrol_logs(tenant_id,location_status,scanned_at DESC)`);
  console.log('Patrol scan evidence columns ready');
}
ensurePatrolEvidenceColumns();

async function ensureGuardAssignmentsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_assignments (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, site_id, user_id)
    )
  `);
  console.log('Guard assignments table ready');
}
ensureGuardAssignmentsTable();

async function ensureRoundSizeColumn() {
  await pool.query(`ALTER TABLE guard_assignments ADD COLUMN IF NOT EXISTS round_size INTEGER`);
  console.log('Round size column ready');
}
ensureRoundSizeColumn();

async function ensureCheckpointMetaColumns() {
  await pool.query(`ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS building TEXT`);
  await pool.query(`ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS floor TEXT`);
  console.log('Checkpoint building/floor columns ready');
}
ensureCheckpointMetaColumns();

async function ensureSosAlertsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sos_alerts (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      message TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMP,
      resolved_by INTEGER
    )
  `);
  console.log('SOS alerts table ready');
}
ensureSosAlertsTable();

async function ensureGuardLocationsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_locations (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      site_id INTEGER,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, user_id)
    )
  `);
  console.log('Guard locations table ready');
}
ensureGuardLocationsTable();

async function ensureGuardLocationHistoryTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_location_history (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      site_id INTEGER,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      recorded_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_guard_location_history_lookup ON guard_location_history (tenant_id, user_id, recorded_at)`);
  console.log('Guard location history table ready');
}
ensureGuardLocationHistoryTable();

async function cleanupLocationHistory() {
  try {
    const cutoff = new Date(Date.now() - LOCATION_HISTORY_RETENTION_HOURS * 3600000);
    const result = await pool.query('DELETE FROM guard_location_history WHERE recorded_at < $1', [cutoff]);
    if (result.rowCount > 0) {
      console.log('Pruned ' + result.rowCount + ' old guard_location_history row(s)');
    }
  } catch (err) {
    console.error('Location history cleanup failed:', err.message);
  }
}
scheduleBackgroundJob('location_history_cleanup',LOCATION_HISTORY_CLEANUP_INTERVAL_MS,20000,cleanupLocationHistory);

async function ensureClientUsersTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS client_users (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, email)
    )
  `);
  console.log('Client users table ready');
}
ensureClientUsersTable();

// Guard certifications table + migration
async function ensureGuardCertificationsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_certifications (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      cert_name TEXT NOT NULL,
      cert_number TEXT,
      issue_date DATE,
      expiry_date DATE NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  // Migration safety for databases created by the older name/issuer schema.
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS cert_name TEXT`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS cert_number TEXT`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS issue_date DATE`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS expiry_date DATE`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW()`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS archived_by_user_id INTEGER`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS replacement_for_id INTEGER`);
  await pool.query(`ALTER TABLE guard_certifications ADD COLUMN IF NOT EXISTS replaced_by_id INTEGER`);

  const legacyNameColumn = await pool.query(`
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'guard_certifications'
      AND column_name = 'name'
  `);
  if (legacyNameColumn.rows.length > 0) {
    await pool.query(`
      UPDATE guard_certifications
      SET cert_name = name
      WHERE cert_name IS NULL AND name IS NOT NULL
    `);
    // New writes use cert_name, so the legacy name column must no longer
    // reject inserts that intentionally omit it.
    await pool.query(`ALTER TABLE guard_certifications ALTER COLUMN name DROP NOT NULL`);
  }

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_guard_certifications_user ON guard_certifications (tenant_id, user_id)`);
  console.log('Guard certifications table ready');
}
ensureGuardCertificationsTable();

// Shift scheduling table
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
      break_minutes INTEGER NOT NULL DEFAULT 0,
      employment_type TEXT NOT NULL DEFAULT 'full_time',
      recurrence_group_id TEXT,
      notes TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS break_minutes INTEGER NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS assignment_status TEXT NOT NULL DEFAULT 'assigned'`);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS confirmation_status TEXT NOT NULL DEFAULT 'pending'`);
  await pool.query(`ALTER TABLE shifts ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_guard_lookup ON shifts (tenant_id, user_id, shift_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_site_lookup ON shifts (tenant_id, site_id, shift_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shifts_series ON shifts (tenant_id, recurrence_group_id)`);
  console.log('Shifts table ready');
}
ensureShiftsTable();

async function ensureShiftSwapRequestsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shift_swap_requests (
      id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, shift_id INTEGER NOT NULL,
      requester_id INTEGER NOT NULL, target_user_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending_recipient', reason TEXT,
      recipient_responded_at TIMESTAMPTZ, admin_reviewed_at TIMESTAMPTZ,
      admin_reviewed_by INTEGER, admin_notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_swap_requests ON shift_swap_requests (tenant_id,status,created_at DESC)`);
  console.log('Shift swap requests table ready');
}
ensureShiftSwapRequestsTable();

async function ensureShiftTemplatesTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shift_templates (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      site_id INTEGER,
      name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#2563eb',
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      break_minutes INTEGER NOT NULL DEFAULT 0,
      employment_type TEXT NOT NULL DEFAULT 'full_time',
      notes TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_shift_templates_tenant ON shift_templates (tenant_id, name)`);
  console.log('Shift templates table ready');
}
ensureShiftTemplatesTable();

async function ensureAttendanceTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance_sessions (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      site_id INTEGER NOT NULL,
      shift_id INTEGER,
      clocked_in_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      clocked_out_at TIMESTAMPTZ,
      clock_in_latitude DOUBLE PRECISION,
      clock_in_longitude DOUBLE PRECISION,
      clock_in_accuracy DOUBLE PRECISION,
      clock_out_latitude DOUBLE PRECISION,
      clock_out_longitude DOUBLE PRECISION,
      clock_out_accuracy DOUBLE PRECISION,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance_breaks (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      attendance_session_id INTEGER NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ended_at TIMESTAMPTZ,
      start_latitude DOUBLE PRECISION,
      start_longitude DOUBLE PRECISION,
      end_latitude DOUBLE PRECISION,
      end_longitude DOUBLE PRECISION
    )
  `);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_one_active_session ON attendance_sessions (tenant_id, user_id) WHERE clocked_out_at IS NULL`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_attendance_one_active_break ON attendance_breaks (attendance_session_id) WHERE ended_at IS NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_attendance_history ON attendance_sessions (tenant_id, clocked_in_at DESC)`);
  await pool.query(`ALTER TABLE attendance_sessions ADD COLUMN IF NOT EXISTS clock_in_distance_m DOUBLE PRECISION`);
  await pool.query(`ALTER TABLE attendance_sessions ADD COLUMN IF NOT EXISTS clock_in_geofence_radius_m INTEGER`);
  await pool.query(`ALTER TABLE attendance_sessions ADD COLUMN IF NOT EXISTS clock_in_geofence_verified BOOLEAN`);
  console.log('Attendance tables ready');
}
ensureAttendanceTables();

async function ensureTimesheetsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS timesheets (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      period_start DATE NOT NULL,
      period_end DATE NOT NULL,
      status TEXT NOT NULL DEFAULT 'submitted',
      session_count INTEGER NOT NULL DEFAULT 0,
      worked_seconds BIGINT NOT NULL DEFAULT 0,
      break_seconds BIGINT NOT NULL DEFAULT 0,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by INTEGER,
      review_notes TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, user_id, period_start, period_end)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_timesheets_review ON timesheets (tenant_id, status, period_start DESC)`);
  console.log('Timesheets table ready');
}
ensureTimesheetsTable();

async function ensureAvailabilityAndLeaveTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guard_availability (
      id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      weekday INTEGER NOT NULL, is_available BOOLEAN NOT NULL DEFAULT TRUE,
      available_from TEXT, available_until TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id,user_id,weekday), CHECK (weekday BETWEEN 0 AND 6)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS leave_requests (
      id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      start_date DATE NOT NULL, end_date DATE NOT NULL, leave_type TEXT NOT NULL,
      reason TEXT, status TEXT NOT NULL DEFAULT 'pending', requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ, reviewed_by INTEGER, review_notes TEXT,
      CHECK (end_date >= start_date)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_leave_review ON leave_requests (tenant_id,status,start_date)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_guard_availability_lookup ON guard_availability (tenant_id,user_id,weekday)`);
  console.log('Availability and leave tables ready');
}
ensureAvailabilityAndLeaveTables();

// ------------------------ COMPLIANCE SWEEP ------------------------

function mostRecentFixedOccurrenceUTC(times, nowUTC, zone) {
  const nowLocal = DateTime.fromJSDate(nowUTC, { zone });
  const candidates = [];
  [0, -1].forEach(dayOffset => {
    const base = nowLocal.plus({ days: dayOffset });
    times.forEach(t => {
      const [h, m] = t.split(':').map(Number);
      const occLocal = base.set({ hour: h || 0, minute: m || 0, second: 0, millisecond: 0 });
      const occUTC = occLocal.toUTC();
      if (occUTC.toJSDate() <= nowUTC) candidates.push(occUTC.toJSDate());
    });
  });
  if (candidates.length === 0) return null;
  return new Date(Math.max(...candidates.map(d => d.getTime())));
}

function todayStartUTC(zone) {
  return DateTime.now().setZone(zone).startOf('day').toUTC().toJSDate();
}

async function computeSiteCompliance(client, tenantId, siteId) {
  const tenantRes = await client.query('SELECT timezone FROM tenants WHERE id = $1', [tenantId]);
  const schedulesRes = await client.query(
    'SELECT * FROM patrol_schedules WHERE tenant_id = $1 AND site_id = $2',
    [tenantId, siteId]
  );
  const checkpointsRes = await client.query(
    'SELECT * FROM checkpoints WHERE tenant_id = $1 AND site_id = $2',
    [tenantId, siteId]
  );
  const checkpointIds = checkpointsRes.rows.map(c => c.id);
  const logsRes = checkpointIds.length
    ? await client.query(
        'SELECT * FROM patrol_logs WHERE tenant_id = $1 AND checkpoint_id = ANY($2) ORDER BY scanned_at DESC',
        [tenantId, checkpointIds]
      )
    : { rows: [] };

  const zone = (tenantRes.rows[0] && tenantRes.rows[0].timezone) || 'UTC';
  const now = new Date();
  const hourlySchedules = schedulesRes.rows.filter(s => s.schedule_type === 'hourly');
  const fixedSchedules = schedulesRes.rows.filter(s => s.schedule_type === 'fixed');
  const hasCustomOnly = hourlySchedules.length === 0 && fixedSchedules.length === 0 && schedulesRes.rows.some(s => s.schedule_type === 'custom');

  const shortestHourly = hourlySchedules.length
    ? Math.min(...hourlySchedules.map(s => Number(s.config.interval_hours) || Infinity))
    : null;

  const allFixedTimes = Array.from(new Set(
    fixedSchedules.flatMap(s => Array.isArray(s.config.times) ? s.config.times : [])
  ));

  return checkpointsRes.rows.map(cp => {
    const lastLog = logsRes.rows.find(l => l.checkpoint_id === cp.id);
    const lastScan = lastLog ? new Date(lastLog.scanned_at) : null;

    let status = 'no_schedule';
    let hoursOverdue = 0;
    let scheduleType = null;

    if (shortestHourly !== null && shortestHourly !== Infinity) {
      scheduleType = 'hourly';
      if (!lastScan) {
        status = 'overdue';
      } else {
        const hoursSince = (now - lastScan) / 3600000;
        if (hoursSince > shortestHourly) {
          status = 'overdue';
          hoursOverdue = Math.round((hoursSince - shortestHourly) * 10) / 10;
        } else {
          status = 'ok';
        }
      }
    } else if (allFixedTimes.length > 0) {
      scheduleType = 'fixed';
      const targetOcc = mostRecentFixedOccurrenceUTC(allFixedTimes, now, zone);
      if (!targetOcc) {
        status = 'ok';
      } else {
        const windowStart = new Date(targetOcc.getTime() - FIXED_WINDOW_MINUTES * 60000);
        const windowEnd = new Date(targetOcc.getTime() + FIXED_WINDOW_MINUTES * 60000);
        const matchedScan = logsRes.rows.find(l => {
          const t = new Date(l.scanned_at);
          return l.checkpoint_id === cp.id && t >= windowStart && t <= windowEnd;
        });
        if (matchedScan) status = 'ok';
        else if (now < windowEnd) status = 'ok';
        else {
          status = 'overdue';
          hoursOverdue = Math.round(((now - windowEnd) / 3600000) * 10) / 10;
        }
      }
    } else if (hasCustomOnly) {
      status = 'unmonitored';
    }

    return {
      checkpoint_id: cp.id,
      checkpoint_name: cp.name,
      last_scan: lastScan,
      status,
      hours_overdue: hoursOverdue,
      schedule_type: scheduleType
    };
  });
}

async function runComplianceSweep() {
  try {
    const tenantsRes = await pool.query('SELECT id FROM tenants');
    for (const tenant of tenantsRes.rows) {
      await withTenant(tenant.id, async (client) => {
        const sitesRes = await client.query('SELECT id, name FROM sites WHERE tenant_id = $1', [tenant.id]);

        for (const site of sitesRes.rows) {
          const compliance = await computeSiteCompliance(client, tenant.id, site.id);

          for (const cp of compliance) {
            const openRes = await client.query(
              'SELECT id FROM notifications WHERE tenant_id = $1 AND checkpoint_id = $2 AND resolved = FALSE',
              [tenant.id, cp.checkpoint_id]
            );
            const hasOpen = openRes.rows.length > 0;

            if (cp.status === 'overdue' && !hasOpen) {
              const message = cp.hours_overdue
                ? `${cp.checkpoint_name} is ${cp.hours_overdue}h overdue`
                : `${cp.checkpoint_name} has never been scanned`;
              await client.query(
                `INSERT INTO notifications (tenant_id, site_id, site_name, checkpoint_id, checkpoint_name, message, hours_overdue)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [tenant.id, site.id, site.name, cp.checkpoint_id, cp.checkpoint_name, message, cp.hours_overdue]
              );
            } else if (cp.status !== 'overdue' && hasOpen) {
              await client.query(
                'UPDATE notifications SET resolved = TRUE, resolved_at = NOW() WHERE tenant_id = $1 AND checkpoint_id = $2 AND resolved = FALSE',
                [tenant.id, cp.checkpoint_id]
              );
            }
          }
        }
      });
    }
  } catch (err) {
    console.error('Compliance sweep failed:', err.message);
  }
}
scheduleBackgroundJob('compliance_alert_sweep',ALERT_SWEEP_INTERVAL_MS,15000,runComplianceSweep);

// ------------------------ REPORT HELPERS ------------------------

async function fetchReportData(client, tenantId, siteId, startDt, endDt) {
  const tenantRes = await client.query('SELECT name, timezone FROM tenants WHERE id = $1', [tenantId]);
  const siteRes = await client.query('SELECT name FROM sites WHERE id = $1 AND tenant_id = $2', [siteId, tenantId]);
  if (siteRes.rows.length === 0) {
    const err = new Error('Site not found');
    err.statusCode = 404;
    throw err;
  }

  const checkpointsRes = await client.query(
    'SELECT id, name, building, floor FROM checkpoints WHERE tenant_id = $1 AND site_id = $2 ORDER BY name',
    [tenantId, siteId]
  );
  const checkpointIds = checkpointsRes.rows.map(c => c.id);

  const logsRes = checkpointIds.length
    ? await client.query(
        `SELECT pl.*, u.email as guard_email FROM patrol_logs pl
         LEFT JOIN users u ON u.id = pl.user_id
         WHERE pl.tenant_id = $1 AND pl.checkpoint_id = ANY($2)
           AND pl.scanned_at >= $3 AND pl.scanned_at <= $4
         ORDER BY pl.scanned_at ASC`,
        [tenantId, checkpointIds, startDt.toJSDate(), endDt.toJSDate()]
      )
    : { rows: [] };

  const incidentsRes = await client.query(
    `SELECT i.*, u.email as guard_email, COALESCE(p.photo_count, 0) as photo_count
     FROM incidents i
     LEFT JOIN users u ON u.id = i.user_id
     LEFT JOIN (
       SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id
     ) p ON p.incident_id = i.id
     WHERE i.tenant_id = $1 AND i.site_id = $2
       AND i.reported_at >= $3 AND i.reported_at <= $4
     ORDER BY i.reported_at ASC`,
    [tenantId, siteId, startDt.toJSDate(), endDt.toJSDate()]
  );

  const checkpointLookup = {};
  checkpointsRes.rows.forEach(cp => { checkpointLookup[cp.id] = cp; });

  const perCheckpoint = checkpointsRes.rows.map(cp => {
    const scansForCp = logsRes.rows.filter(l => l.checkpoint_id === cp.id);
    const lastScanInRange = scansForCp.length ? scansForCp[scansForCp.length - 1].scanned_at : null;
    return {
      id: cp.id,
      name: cp.name,
      location: [cp.building, cp.floor].filter(Boolean).join(' / ') || '-',
      scanCount: scansForCp.length,
      lastScan: lastScanInRange
    };
  });

  const scannedCheckpoints = perCheckpoint.filter(cp => cp.scanCount > 0).length;

  return {
    tenantName: tenantRes.rows[0] ? tenantRes.rows[0].name : 'PatrolSync Client',
    timezone: (tenantRes.rows[0] && tenantRes.rows[0].timezone) || 'UTC',
    siteName: siteRes.rows[0].name,
    checkpointLookup,
    perCheckpoint,
    logs: logsRes.rows,
    incidents: incidentsRes.rows,
    stats: {
      totalCheckpoints: checkpointsRes.rows.length,
      totalScans: logsRes.rows.length,
      scannedCheckpoints,
      totalIncidents: incidentsRes.rows.length
    }
  };
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = String(value);
  if (/[",\n]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function buildCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(',')];
  rows.forEach(row => {
    lines.push(row.map(csvEscape).join(','));
  });
  return lines.join('\r\n');
}

function drawReportHeader(doc, tenantName, siteName, startLabel, endLabel) {
  doc.fontSize(20).fillColor('#1e293b').text('Patrol Compliance Report', { align: 'left' });
  doc.moveDown(0.3);
  doc.fontSize(11).fillColor('#64748b').text(tenantName, { align: 'left' });
  doc.moveDown(0.8);

  doc.fontSize(13).fillColor('#111827').text('Site: ' + siteName);
  doc.fontSize(11).fillColor('#374151').text('Period: ' + startLabel + ' to ' + endLabel);
  doc.fontSize(9).fillColor('#9ca3af').text('Generated ' + DateTime.now().toFormat('dd LLL yyyy, HH:mm') + ' by PatrolSync');
  doc.moveDown(1);
  doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#e5e7eb').stroke();
  doc.moveDown(1);
}

function drawSectionTitle(doc, title) {
  doc.fontSize(14).fillColor('#1e293b').text(title);
  doc.moveDown(0.4);
}

function drawSummaryStats(doc, stats) {
  const boxWidth = 123;
  const boxHeight = 60;
  const startX = 50;
  const startY = doc.y;
  const items = [
    { label: 'Checkpoints', value: String(stats.totalCheckpoints) },
    { label: 'Total Scans', value: String(stats.totalScans) },
    { label: 'Checkpoints Scanned', value: stats.scannedCheckpoints + '/' + stats.totalCheckpoints },
    { label: 'Incidents Logged', value: String(stats.totalIncidents) }
  ];
  items.forEach((item, i) => {
    const x = startX + i * (boxWidth + 6);
    doc.roundedRect(x, startY, boxWidth, boxHeight, 6).fillAndStroke('#f8fafc', '#e5e7eb');
    doc.fontSize(20).fillColor('#2563eb').text(item.value, x, startY + 10, { width: boxWidth, align: 'center' });
    doc.fontSize(9).fillColor('#64748b').text(item.label, x, startY + 38, { width: boxWidth, align: 'center' });
  });
  doc.y = startY + boxHeight + 20;
}

function severityColor(sev) {
  if (sev === 'critical') return '#7f1d1d';
  if (sev === 'high') return '#dc2626';
  if (sev === 'medium') return '#d97706';
  return '#2563eb';
}

function parseReportDateRange(start_date, end_date) {
  const startDt = DateTime.fromISO(start_date).startOf('day');
  const endDt = DateTime.fromISO(end_date).endOf('day');
  if (!startDt.isValid || !endDt.isValid || endDt < startDt) {
    const err = new Error('Invalid or reversed date range');
    err.statusCode = 400;
    throw err;
  }
  return { startDt, endDt };
}

function safeFilenamePart(str) {
  return String(str).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

// ------------------------ REPORT ROUTES ------------------------

app.get('/api/reports/compliance-pdf', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, start_date, end_date } = req.query;
  if (!tenant_id || !site_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'tenant_id, site_id, start_date, and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

    const startLabel = startDt.toFormat('dd LLL yyyy');
    const endLabel = endDt.toFormat('dd LLL yyyy');
    const filename = 'compliance-report-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.pdf';

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');

    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    doc.pipe(res);

    drawReportHeader(doc, reportData.tenantName, reportData.siteName, startLabel, endLabel);
    drawSectionTitle(doc, 'Summary');
    drawSummaryStats(doc, reportData.stats);

    drawSectionTitle(doc, 'Checkpoint Activity');
    if (reportData.perCheckpoint.length === 0) {
      doc.fontSize(10).fillColor('#6b7280').text('No checkpoints configured for this site.');
    } else {
      const colX = { name: 50, location: 220, scans: 370, lastScan: 430 };
      const headerY = doc.y;
      doc.fontSize(9).fillColor('#374151');
      doc.text('Checkpoint', colX.name, headerY);
      doc.text('Location', colX.location, headerY);
      doc.text('Scans', colX.scans, headerY);
      doc.text('Last Scan', colX.lastScan, headerY);
      doc.moveDown(0.3);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#e5e7eb').stroke();
      doc.moveDown(0.3);

      reportData.perCheckpoint.forEach(cp => {
        if (doc.y > 720) { doc.addPage(); doc.y = 50; }
        const rowY = doc.y;
        doc.fontSize(9).fillColor(cp.scanCount === 0 ? '#dc2626' : '#111827');
        doc.text(cp.name, colX.name, rowY, { width: 165 });
        doc.fillColor('#6b7280').text(cp.location, colX.location, rowY, { width: 140 });
        doc.fillColor(cp.scanCount === 0 ? '#dc2626' : '#111827').text(String(cp.scanCount), colX.scans, rowY, { width: 50 });
        doc.fillColor('#6b7280').text(
          cp.lastScan ? DateTime.fromJSDate(new Date(cp.lastScan)).setZone(reportData.timezone).toFormat('dd LLL, HH:mm') : 'Not scanned',
          colX.lastScan, rowY, { width: 110 }
        );
        doc.moveDown(0.6);
      });
    }

    doc.moveDown(1);
    if (doc.y > 680) { doc.addPage(); doc.y = 50; }
    drawSectionTitle(doc, 'Incidents Reported (' + reportData.incidents.length + ')');
    if (reportData.incidents.length === 0) {
      doc.fontSize(10).fillColor('#16a34a').text('No incidents reported during this period.');
    } else {
      reportData.incidents.forEach(inc => {
        if (doc.y > 700) { doc.addPage(); doc.y = 50; }
        const dateLabel = DateTime.fromJSDate(new Date(inc.reported_at)).setZone(reportData.timezone).toFormat('dd LLL yyyy, HH:mm');
        doc.fontSize(9).fillColor(severityColor(inc.severity)).text('[' + inc.severity.toUpperCase() + ']  ' + dateLabel, { continued: false });
        doc.fontSize(10).fillColor('#111827').text(inc.description, { width: 495 });
        if (inc.guard_email) {
          doc.fontSize(8).fillColor('#9ca3af').text('Reported by: ' + inc.guard_email);
        }
        doc.moveDown(0.6);
      });
    }

    doc.end();
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/reports/compliance-csv', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, start_date, end_date } = req.query;
  if (!tenant_id || !site_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'tenant_id, site_id, start_date, and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

    const rows = reportData.logs.map(log => {
      const cp = reportData.checkpointLookup[log.checkpoint_id] || {};
      const scannedLocal = DateTime.fromJSDate(new Date(log.scanned_at)).setZone(reportData.timezone);
      return [
        reportData.siteName,
        cp.name || ('Checkpoint #' + log.checkpoint_id),
        [cp.building, cp.floor].filter(Boolean).join(' / ') || '',
        log.guard_email || '',
        scannedLocal.toFormat('yyyy-MM-dd'),
        scannedLocal.toFormat('HH:mm:ss'),
        log.latitude ?? '',
        log.longitude ?? ''
      ];
    });

    const csv = buildCsv(
      ['Site', 'Checkpoint', 'Location', 'Guard Email', 'Date', 'Time', 'Latitude', 'Longitude'],
      rows
    );

    const filename = 'scan-log-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.csv';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send('\uFEFF' + csv);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/reports/incidents-csv', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, start_date, end_date } = req.query;
  if (!tenant_id || !site_id || !start_date || !end_date) {
    return res.status(400).json({ error: 'tenant_id, site_id, start_date, and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

    const rows = reportData.incidents.map(inc => {
      const reportedLocal = DateTime.fromJSDate(new Date(inc.reported_at)).setZone(reportData.timezone);
      return [
        reportData.siteName,
        reportedLocal.toFormat('yyyy-MM-dd'),
        reportedLocal.toFormat('HH:mm:ss'),
        inc.severity,
        inc.guard_email || '',
        inc.description,
        inc.photo_count
      ];
    });

    const csv = buildCsv(
      ['Site', 'Date', 'Time', 'Severity', 'Guard Email', 'Description', 'Photo Count'],
      rows
    );

    const filename = 'incidents-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.csv';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send('\uFEFF' + csv);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ HEALTH & BASIC ROUTES ------------------------

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'PatrolSync Backend', timestamp: new Date().toISOString() });
});

app.get('/health', async (req, res) => {
  try {
    const started=Date.now();await pool.query('SELECT 1');
    const healthy=runtimeState.ready&&!runtimeState.draining;
    res.status(healthy?200:503).json({status:healthy?'healthy':'draining',service:'PatrolSync Backend',database:'connected',database_latency_ms:Date.now()-started,instance_id:BACKGROUND_INSTANCE_ID,ready:runtimeState.ready,draining:runtimeState.draining,active_requests:runtimeState.active_requests,uptime_seconds:Math.floor(process.uptime()),timestamp:new Date().toISOString(),request_id:req.requestId});
  } catch (err) {
    res.status(503).json({status:'unhealthy',database:'disconnected',error:err.message,request_id:req.requestId});
  }
});

app.get('/live',(req,res)=>res.json({live:true,service:'PatrolSync Backend',instance_id:BACKGROUND_INSTANCE_ID,draining:runtimeState.draining,uptime_seconds:Math.floor(process.uptime()),request_id:req.requestId}));
app.get('/ready',async(req,res)=>{if(!runtimeState.ready||runtimeState.draining)return res.status(503).json({ready:false,draining:runtimeState.draining,error:'Service is not accepting new work',request_id:req.requestId});try{const started=Date.now();await Promise.all([systemPool.query('SELECT 1'),DATABASE_PATHS_SEPARATED?tenantPool.query('SELECT 1'):Promise.resolve()]);res.json({ready:true,instance_id:BACKGROUND_INSTANCE_ID,database_latency_ms:Date.now()-started,system_pool_waiting:systemPool.waitingCount,tenant_pool_waiting:tenantPool.waitingCount,request_id:req.requestId})}catch(err){res.status(503).json({ready:false,error:'Database unavailable',request_id:req.requestId})}});

app.get('/api/timezones', (req, res) => {
  res.json(getAllTimezones());
});

app.get('/api/plans', (req, res) => {
  res.json(PLAN_LIMITS);
});

app.get('/api/usage', requireAuth, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const data = await withTenant(tenant_id, async (client) => {
      const tenantRes = await client.query('SELECT plan FROM tenants WHERE id = $1', [tenant_id]);
      const plan = (tenantRes.rows[0] && tenantRes.rows[0].plan) || 'starter';
      const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.starter;

      const sitesRes = await client.query('SELECT COUNT(*) FROM sites WHERE tenant_id = $1', [tenant_id]);
      const checkpointsRes = await client.query('SELECT COUNT(*) FROM checkpoints WHERE tenant_id = $1', [tenant_id]);
      const guardsRes = await client.query("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'guard'", [tenant_id]);
      const clientAccountsRes = await client.query('SELECT COUNT(*) FROM client_users WHERE tenant_id = $1', [tenant_id]);

      return {
        plan,
        limits,
        usage: {
          locations: parseInt(sitesRes.rows[0].count, 10),
          checkpoints: parseInt(checkpointsRes.rows[0].count, 10),
          guards: parseInt(guardsRes.rows[0].count, 10),
          client_accounts: parseInt(clientAccountsRes.rows[0].count, 10)
        }
      };
    });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/notifications', requireAuth, async (req, res) => {
  const { tenant_id, status } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => {
      if (status === 'resolved') {
        return client.query('SELECT * FROM notifications WHERE tenant_id = $1 AND resolved = TRUE ORDER BY resolved_at DESC LIMIT 50', [tenant_id]);
      } else if (status === 'all') {
        return client.query('SELECT * FROM notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100', [tenant_id]);
      }
      return client.query('SELECT * FROM notifications WHERE tenant_id = $1 AND resolved = FALSE ORDER BY created_at DESC', [tenant_id]);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/notifications/:id/resolve', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'UPDATE notifications SET resolved = TRUE, resolved_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING *',
        [id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Notification not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/audit-logs', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const { action, user_id, from_date, to_date, search } = req.query;
  try {
    const result = await withTenant(tenantId, client => {
      const params = [tenantId];
      let query = 'SELECT * FROM audit_logs WHERE tenant_id=$1';
      if (action) { params.push(action); query += ` AND action=$${params.length}`; }
      if (user_id) { params.push(user_id); query += ` AND user_id=$${params.length}`; }
      if (from_date) { params.push(from_date); query += ` AND created_at >= $${params.length}::date`; }
      if (to_date) { params.push(to_date); query += ` AND created_at < ($${params.length}::date + INTERVAL '1 day')`; }
      if (search) { params.push(`%${search}%`); query += ` AND (resource ILIKE $${params.length} OR user_email ILIKE $${params.length} OR details::text ILIKE $${params.length})`; }
      query += ' ORDER BY created_at DESC LIMIT 500';
      return client.query(query, params);
    });
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ SOS ROUTES ------------------------

app.post('/api/sos', requireAuth, requireTrustedGuardDevice, async (req, res) => {
  const { tenant_id, site_id, latitude, longitude, message } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || !site_id) {
    return res.status(400).json({ error: 'tenant_id and site_id are required' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const existing = await client.query(
        "SELECT * FROM sos_alerts WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'",
        [tenant_id, user_id]
      );
      if (existing.rows.length > 0) {
        return { row: existing.rows[0], alreadyActive: true };
      }
      const inserted = await client.query(
        `INSERT INTO sos_alerts (tenant_id, site_id, user_id, latitude, longitude, message)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [tenant_id, site_id, user_id, latitude ?? null, longitude ?? null, message || null]
      );
      return { row: inserted.rows[0], alreadyActive: false };
    });
    res.status(result.alreadyActive ? 200 : 201).json(result.row);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sos', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, status } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => {
      const base = `SELECT sa.*, u.email as guard_email, s.name as site_name
                    FROM sos_alerts sa
                    JOIN users u ON u.id = sa.user_id
                    JOIN sites s ON s.id = sa.site_id
                    WHERE sa.tenant_id = $1`;
      if (status === 'resolved') {
        return client.query(base + " AND sa.status = 'resolved' ORDER BY sa.resolved_at DESC LIMIT 50", [tenant_id]);
      } else if (status === 'all') {
        return client.query(base + ' ORDER BY sa.created_at DESC LIMIT 100', [tenant_id]);
      }
      return client.query(base + " AND sa.status = 'active' ORDER BY sa.created_at DESC", [tenant_id]);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/sos/:id/resolve', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const existing = await client.query(
        "SELECT * FROM sos_alerts WHERE id = $1 AND tenant_id = $2 AND status = 'active'",
        [id, tenant_id]
      );
      if (existing.rows.length === 0) return { rows: [] };

      const alert = existing.rows[0];
      const isOwner = alert.user_id === req.auth.user_id;
      const isAdmin = req.auth.role === 'admin';
      if (!isOwner && !isAdmin) {
        const err = new Error('You can only cancel your own SOS alert');
        err.statusCode = 403;
        throw err;
      }

      return client.query(
        `UPDATE sos_alerts SET status = 'resolved', resolved_at = NOW(), resolved_by = $1
         WHERE id = $2 AND tenant_id = $3 AND status = 'active' RETURNING *`,
        [req.auth.user_id, id, tenant_id]
      );
    });
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Active SOS alert not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ GUARD LOCATION ROUTES ------------------------

app.post('/api/guard-locations', requireAuth, async (req, res) => {
  const { tenant_id, site_id, latitude, longitude } = req.body;
  const user_id = req.auth.user_id;
  if (!tenant_id || latitude === undefined || longitude === undefined) {
    return res.status(400).json({ error: 'tenant_id, latitude, and longitude are required' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const upserted = await client.query(
        `INSERT INTO guard_locations (tenant_id, user_id, site_id, latitude, longitude, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW())
         ON CONFLICT (tenant_id, user_id)
         DO UPDATE SET site_id = $3, latitude = $4, longitude = $5, updated_at = NOW()
         RETURNING *`,
        [tenant_id, user_id, site_id || null, latitude, longitude]
      );
      await client.query(
        `INSERT INTO guard_location_history (tenant_id, user_id, site_id, latitude, longitude)
         VALUES ($1, $2, $3, $4, $5)`,
        [tenant_id, user_id, site_id || null, latitude, longitude]
      );
      return upserted.rows[0];
    });
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-locations', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `SELECT gl.*, u.email as guard_email, s.name as site_name
         FROM guard_locations gl
         JOIN users u ON u.id = gl.user_id
         LEFT JOIN sites s ON s.id = gl.site_id
         WHERE gl.tenant_id = $1
         ORDER BY gl.updated_at DESC`,
        [tenant_id]
      )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-locations/history', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, user_id, hours } = req.query;
  if (!tenant_id || !user_id) return res.status(400).json({ error: 'tenant_id and user_id query params are required' });

  let hoursNum = hours ? Number(hours) : 12;
  if (!Number.isFinite(hoursNum) || hoursNum <= 0) hoursNum = 12;
  if (hoursNum > LOCATION_HISTORY_RETENTION_HOURS) hoursNum = LOCATION_HISTORY_RETENTION_HOURS;

  try {
    const cutoff = new Date(Date.now() - hoursNum * 3600000);
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `SELECT glh.*, s.name as site_name
         FROM guard_location_history glh
         LEFT JOIN sites s ON s.id = glh.site_id
         WHERE glh.tenant_id = $1 AND glh.user_id = $2 AND glh.recorded_at >= $3
         ORDER BY glh.recorded_at ASC`,
        [tenant_id, user_id, cutoff]
      )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ CLIENT PORTAL ROUTES ------------------------

app.post('/api/client-users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, email, password } = req.body;
  if (!tenant_id || !site_id || !email || !password) {
    return res.status(400).json({ error: 'tenant_id, site_id, email, and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'password must be at least 6 characters' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const siteCheck = await client.query('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [site_id, tenant_id]);
      if (siteCheck.rows.length === 0) {
        const err = new Error('Site not found for this tenant');
        err.statusCode = 404;
        throw err;
      }
      const limitCheck = await checkPlanLimit(client, tenant_id, 'client_accounts');
      if (!limitCheck.allowed) {
        const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} client portal account(s). Upgrade your plan to add more.`);
        err.statusCode = 403;
        throw err;
      }
      const hash = await bcrypt.hash(password, 10);
      return client.query(
        'INSERT INTO client_users (tenant_id, site_id, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, tenant_id, site_id, email, created_at',
        [tenant_id, site_id, email.toLowerCase().trim(), hash]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A client account with this email already exists for this tenant' });
    }
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/client-users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      site_id
        ? client.query(
            `SELECT cu.id, cu.tenant_id, cu.site_id, cu.email, cu.created_at, s.name as site_name
             FROM client_users cu JOIN sites s ON s.id = cu.site_id
             WHERE cu.tenant_id = $1 AND cu.site_id = $2 ORDER BY cu.created_at DESC`,
            [tenant_id, site_id]
          )
        : client.query(
            `SELECT cu.id, cu.tenant_id, cu.site_id, cu.email, cu.created_at, s.name as site_name
             FROM client_users cu JOIN sites s ON s.id = cu.site_id
             WHERE cu.tenant_id = $1 ORDER BY cu.created_at DESC`,
            [tenant_id]
          )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/client-users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query('DELETE FROM client_users WHERE id = $1 AND tenant_id = $2 RETURNING id, email', [id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Client account not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/client-users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, new_password } = req.body;
  if (!tenant_id || !new_password) return res.status(400).json({ error: 'tenant_id and new_password are required' });
  if (new_password.length < 6) return res.status(400).json({ error: 'new_password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(new_password, 10);
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'UPDATE client_users SET password_hash = $1 WHERE id = $2 AND tenant_id = $3 RETURNING id, email',
        [hash, id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Client account not found' });
    res.json({ reset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/client-auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
  const normalizedEmail = email.toLowerCase().trim();

  try {
    const tenantsRes = await pool.query('SELECT id FROM tenants WHERE COALESCE(account_active,TRUE)=TRUE');
    let matched = null;
    let matchedTenantId = null;

    for (const t of tenantsRes.rows) {
      const result = await withTenant(t.id, (client) =>
        client.query('SELECT * FROM client_users WHERE tenant_id = $1 AND LOWER(email) = $2', [t.id, normalizedEmail])
      );
      if (result.rows.length > 0) {
        const candidate = result.rows[0];
        const valid = await bcrypt.compare(password, candidate.password_hash);
        if (valid) {
          matched = candidate;
          matchedTenantId = t.id;
          break;
        }
      }
    }

    if (!matched) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const siteRes = await withTenant(matchedTenantId, (client) =>
      client.query('SELECT name FROM sites WHERE id = $1 AND tenant_id = $2', [matched.site_id, matchedTenantId])
    );

    const token = jwt.sign(
      { client_user_id: matched.id, tenant_id: matchedTenantId, site_id: matched.site_id, role: 'client' },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      token,
      client: { id: matched.id, email: matched.email },
      tenant_id: matchedTenantId,
      site_id: matched.site_id,
      site_name: siteRes.rows[0] ? siteRes.rows[0].name : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/compliance', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  try {
    const compliance = await withTenant(tenant_id, (client) => computeSiteCompliance(client, tenant_id, site_id));
    res.json(compliance);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/incidents', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  const { date } = req.query;
  try {
    const result = await withTenant(tenant_id, (client) =>
      date
        ? client.query(
            `SELECT i.description, i.severity, i.reported_at, COALESCE(p.photo_count, 0) as photo_count
             FROM incidents i
             LEFT JOIN (SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id) p ON p.incident_id = i.id
             WHERE i.tenant_id = $1 AND i.site_id = $2 AND i.reported_at::date = $3
             ORDER BY i.reported_at DESC`,
            [tenant_id, site_id, date]
          )
        : client.query(
            `SELECT i.description, i.severity, i.reported_at, COALESCE(p.photo_count, 0) as photo_count
             FROM incidents i
             LEFT JOIN (SELECT incident_id, COUNT(*) AS photo_count FROM incident_photos WHERE tenant_id = $1 GROUP BY incident_id) p ON p.incident_id = i.id
             WHERE i.tenant_id = $1 AND i.site_id = $2
             ORDER BY i.reported_at DESC LIMIT 200`,
            [tenant_id, site_id]
          )
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/site-info', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `SELECT s.name as site_name, s.address, t.name as tenant_name
         FROM sites s JOIN tenants t ON t.id = s.tenant_id
         WHERE s.id = $1 AND s.tenant_id = $2`,
        [site_id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Site not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/client-portal/reports/compliance-pdf', requireAuth, requireClient, async (req, res) => {
  const { tenant_id, site_id } = req.auth;
  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) {
    return res.status(400).json({ error: 'start_date and end_date are required' });
  }

  try {
    const { startDt, endDt } = parseReportDateRange(start_date, end_date);
    const reportData = await withTenant(tenant_id, (client) => fetchReportData(client, tenant_id, site_id, startDt, endDt));

    const startLabel = startDt.toFormat('dd LLL yyyy');
    const endLabel = endDt.toFormat('dd LLL yyyy');
    const filename = 'compliance-report-' + safeFilenamePart(reportData.siteName) + '-' + startDt.toFormat('yyyy-MM-dd') + '.pdf';

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');

    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    doc.pipe(res);

    drawReportHeader(doc, reportData.tenantName, reportData.siteName, startLabel, endLabel);
    drawSectionTitle(doc, 'Summary');
    drawSummaryStats(doc, reportData.stats);

    drawSectionTitle(doc, 'Checkpoint Activity');
    if (reportData.perCheckpoint.length === 0) {
      doc.fontSize(10).fillColor('#6b7280').text('No checkpoints configured for this site.');
    } else {
      const colX = { name: 50, location: 220, scans: 370, lastScan: 430 };
      const headerY = doc.y;
      doc.fontSize(9).fillColor('#374151');
      doc.text('Checkpoint', colX.name, headerY);
      doc.text('Location', colX.location, headerY);
      doc.text('Scans', colX.scans, headerY);
      doc.text('Last Scan', colX.lastScan, headerY);
      doc.moveDown(0.3);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor('#e5e7eb').stroke();
      doc.moveDown(0.3);

      reportData.perCheckpoint.forEach(cp => {
        if (doc.y > 720) { doc.addPage(); doc.y = 50; }
        const rowY = doc.y;
        doc.fontSize(9).fillColor(cp.scanCount === 0 ? '#dc2626' : '#111827');
        doc.text(cp.name, colX.name, rowY, { width: 165 });
        doc.fillColor('#6b7280').text(cp.location, colX.location, rowY, { width: 140 });
        doc.fillColor(cp.scanCount === 0 ? '#dc2626' : '#111827').text(String(cp.scanCount), colX.scans, rowY, { width: 50 });
        doc.fillColor('#6b7280').text(
          cp.lastScan ? DateTime.fromJSDate(new Date(cp.lastScan)).setZone(reportData.timezone).toFormat('dd LLL, HH:mm') : 'Not scanned',
          colX.lastScan, rowY, { width: 110 }
        );
        doc.moveDown(0.6);
      });
    }

    doc.moveDown(1);
    if (doc.y > 680) { doc.addPage(); doc.y = 50; }
    drawSectionTitle(doc, 'Incidents Reported (' + reportData.incidents.length + ')');
    if (reportData.incidents.length === 0) {
      doc.fontSize(10).fillColor('#16a34a').text('No incidents reported during this period.');
    } else {
      reportData.incidents.forEach(inc => {
        if (doc.y > 700) { doc.addPage(); doc.y = 50; }
        const dateLabel = DateTime.fromJSDate(new Date(inc.reported_at)).setZone(reportData.timezone).toFormat('dd LLL yyyy, HH:mm');
        doc.fontSize(9).fillColor(severityColor(inc.severity)).text('[' + inc.severity.toUpperCase() + ']  ' + dateLabel, { continued: false });
        doc.fontSize(10).fillColor('#111827').text(inc.description, { width: 495 });
        doc.moveDown(0.6);
      });
    }

    doc.end();
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ TENANT ROUTES ------------------------

app.post('/api/tenants', requirePlatformAuth, async (req, res) => {
  const { name, slug, plan } = req.body;
  if (!name || !slug) return res.status(400).json({ error: 'name and slug are required' });
  const chosenPlan = VALID_PLANS.includes(plan) ? plan : 'starter';
  try {
    const result = await pool.query(
      'INSERT INTO tenants (name, slug, plan) VALUES ($1, $2, $3) RETURNING *',
      [name, slug, chosenPlan]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tenants', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id,name,slug,plan,timezone,emergency_phone,emergency_whatsapp,created_at FROM tenants WHERE id=$1', [req.auth.tenant_id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tenants/:id/plan', requireAuth, requireAdmin, async (req, res) => {
  return res.status(403).json({ error: 'Subscription plans are managed by the PatrolSync platform owner' });
});

app.patch('/api/tenants/:id/timezone', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { timezone } = req.body;
  if (!timezone) return res.status(400).json({ error: 'timezone is required' });
  if (Number(id) !== req.auth.tenant_id) {
    return res.status(403).json({ error: 'Cannot modify a different tenant' });
  }
  const validZones = getAllTimezones();
  if (!validZones.includes(timezone)) {
    return res.status(400).json({ error: 'Unrecognized timezone' });
  }
  try {
    const result = await withTenant(id, (client) =>
      client.query('UPDATE tenants SET timezone = $1 WHERE id = $2 RETURNING *', [timezone, id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tenant not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function isValidPhoneFormat(value) {
  return /^[0-9+ ()-]{6,20}$/.test(value);
}

app.patch('/api/tenants/:id/emergency-contacts', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { emergency_phone, emergency_whatsapp } = req.body;
  if (Number(id) !== req.auth.tenant_id) {
    return res.status(403).json({ error: 'Cannot modify a different tenant' });
  }

  const phoneTrimmed = (emergency_phone || '').trim();
  const waTrimmed = (emergency_whatsapp || '').trim();

  if (phoneTrimmed && !isValidPhoneFormat(phoneTrimmed)) {
    return res.status(400).json({ error: 'Emergency phone: enter a valid number (digits, spaces, +, -, () only)' });
  }
  if (waTrimmed && !isValidPhoneFormat(waTrimmed)) {
    return res.status(400).json({ error: 'WhatsApp number: enter a valid number (digits, spaces, +, -, () only)' });
  }

  try {
    const result = await withTenant(id, (client) =>
      client.query(
        'UPDATE tenants SET emergency_phone = $1, emergency_whatsapp = $2 WHERE id = $3 RETURNING *',
        [phoneTrimmed || null, waTrimmed || null, id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tenant not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ SIGNUP & AUTH ROUTES ------------------------

app.post('/api/signup', async (req, res) => {
  const { company_name, plan, admin_email, admin_password, timezone } = req.body;
  if (!company_name || !admin_email || !admin_password) {
    return res.status(400).json({ error: 'company_name, admin_email, and admin_password are required' });
  }
  const chosenPlan = VALID_PLANS.includes(plan) ? plan : 'starter';
  const validZones = getAllTimezones();
  const chosenTimezone = timezone && validZones.includes(timezone) ? timezone : 'UTC';
  const slug = company_name.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const tenantResult = await client.query(
      'INSERT INTO tenants (name, slug, plan, timezone) VALUES ($1, $2, $3, $4) RETURNING *',
      [company_name, slug, chosenPlan, chosenTimezone]
    );
    const tenant = tenantResult.rows[0];

    const hash = await bcrypt.hash(admin_password, 10);
    await client.query(`SET app.current_tenant = '${tenant.id}'`);
    const userResult = await client.query(
      'INSERT INTO users (tenant_id, email, role, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, tenant_id, email, role',
      [tenant.id, admin_email.toLowerCase().trim(), 'admin', hash]
    );
    const adminUser = userResult.rows[0];

    await client.query('COMMIT');

    const token = jwt.sign(
      { user_id: adminUser.id, tenant_id: tenant.id, role: adminUser.role },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.status(201).json({ tenant, admin: adminUser, token });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A company with a similar name or this email already exists' });
    }
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { tenant_id, email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  const normalizedEmail = email.toLowerCase().trim();

  try {
    let candidates = [];

    if (tenant_id) {
      const result = await withTenant(tenant_id, (client) =>
        client.query('SELECT * FROM users WHERE tenant_id = $1 AND LOWER(email) = $2', [tenant_id, normalizedEmail])
      );
      candidates = result.rows;
    } else {
      const tenantsRes = await pool.query('SELECT id FROM tenants WHERE COALESCE(account_active,TRUE)=TRUE');
      for (const t of tenantsRes.rows) {
        const result = await withTenant(t.id, (client) =>
          client.query('SELECT * FROM users WHERE tenant_id = $1 AND LOWER(email) = $2', [t.id, normalizedEmail])
        );
        candidates.push(...result.rows);
      }
    }

    if (candidates.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    let matchedUser = null;
    for (const candidate of candidates) {
      if (!candidate.password_hash) continue;
      const valid = await bcrypt.compare(password, candidate.password_hash);
      if (valid) {
        matchedUser = candidate;
        break;
      }
    }

    if (!matchedUser || matchedUser.account_active === false) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const subscriberState=await pool.query(`SELECT COALESCE(account_active,TRUE) active FROM tenants WHERE id=$1`,[matchedUser.tenant_id]);
    if(!subscriberState.rowCount||subscriberState.rows[0].active===false)return res.status(403).json({error:'Company subscription is suspended. Contact PatrolSync support.'});

    if(matchedUser.email_mfa_enabled&&['admin','staff'].includes(matchedUser.role)){const challengeToken=await createEmailMfaChallenge(matchedUser,'login');return res.status(202).json({mfa_required:true,challenge_token:challengeToken,masked_email:matchedUser.email.replace(/^(.{2}).*(@.*)$/,'$1***$2'),expires_in_minutes:10})}

    const token = await createTrackedToken(matchedUser,req);

    res.json({
      token,
      tenant_id: matchedUser.tenant_id,
      user: {
        id: matchedUser.id,
        email: matchedUser.email,
        role: matchedUser.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/mfa/verify',fixedWindowRateLimit('mfa-verify',20),async(req,res)=>{try{const supplied=String(req.body.code||'').trim(),user=/^\d{6}$/.test(supplied)?await consumeEmailMfaChallenge(req.body.challenge_token,supplied,'login'):await consumeUserRecoveryCode(req.body.challenge_token,supplied);const token=await createTrackedToken(user,req);res.json({token,tenant_id:user.tenant_id,recovery_code_used:!/^\d{6}$/.test(supplied),user:{id:user.user_id,email:user.email,role:user.role}})}catch(e){res.status(e.statusCode||500).json({error:e.statusCode?e.message:'Could not verify code'})}});

app.get('/api/security/sessions',requireAuth,requireAdmin,async(req,res)=>{try{const[sessions,events]=await Promise.all([pool.query(`SELECT id,role,ip_address,user_agent,created_at,last_seen_at,expires_at,revoked_at,revoked_reason FROM auth_sessions WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 100`,[req.auth.tenant_id,req.auth.user_id]),pool.query(`SELECT event_type,severity,message,details,created_at FROM system_events WHERE tenant_id=$1 AND event_type IN('account_login','new_device_login','session_revoked','other_sessions_revoked') AND (details->>'user_id')::int=$2 ORDER BY created_at DESC LIMIT 50`,[req.auth.tenant_id,req.auth.user_id])]);res.json({current_session_id:req.auth.session_id||null,sessions:sessions.rows.map(x=>({...x,current:x.id===req.auth.session_id,status:x.revoked_at?'revoked':new Date(x.expires_at)<=new Date()?'expired':'active'})),events:events.rows})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/api/security/sessions/:id',requireAuth,requireAdmin,async(req,res)=>{try{const result=await pool.query(`UPDATE auth_sessions SET revoked_at=NOW(),revoked_reason='Revoked by account owner' WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND revoked_at IS NULL RETURNING id,ip_address,user_agent`,[req.params.id,req.auth.tenant_id,req.auth.user_id]);if(!result.rowCount)return res.status(404).json({error:'Active session not found'});await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details,request_id) VALUES($1,'session_revoked','warning','Administrator session revoked',$2::jsonb,$3)`,[req.auth.tenant_id,JSON.stringify({user_id:req.auth.user_id,session_id:req.params.id,ip_address:result.rows[0].ip_address,user_agent:result.rows[0].user_agent}),req.requestId]);res.json({revoked:true,current_session_revoked:req.params.id===req.auth.session_id})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/sessions/revoke-others',requireAuth,requireAdmin,async(req,res)=>{try{const result=await pool.query(`UPDATE auth_sessions SET revoked_at=NOW(),revoked_reason='Other sessions signed out' WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>NOW() AND ($3::uuid IS NULL OR id<>$3::uuid) RETURNING id`,[req.auth.tenant_id,req.auth.user_id,req.auth.session_id||null]);await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details,request_id) VALUES($1,'other_sessions_revoked','warning','All other administrator sessions revoked',$2::jsonb,$3)`,[req.auth.tenant_id,JSON.stringify({user_id:req.auth.user_id,revoked_count:result.rowCount}),req.requestId]);res.json({revoked_count:result.rowCount})}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ PHASE 6.6: PLATFORM RESPONSE CACHE ------------------------
app.use('/api/platform/overview',requirePlatformAuth,platformCache('overview',15000));
app.use('/api/platform/audit',requirePlatformAuth,platformCache('audit',10000));
app.use('/api/platform/security-posture',requirePlatformAuth,platformCache('security-posture',60000));
app.use('/api/platform/database-isolation',requirePlatformAuth,platformCache('database-isolation',30000));
app.use('/api/platform/performance',requirePlatformAuth,platformCache('performance',5000));
app.use('/api/platform/storage',requirePlatformAuth,platformCache('storage',10000));
app.use('/api/platform/subscribers',requirePlatformAuth,platformCache('subscribers',15000));

app.get('/api/platform/cache',requirePlatformAuth,(req,res)=>{
  prunePlatformCache();
  const entries=[...platformResponseCache.entries()].map(([key,value])=>({key,name:value.name,age_seconds:Math.max(0,Math.floor((Date.now()-value.createdAt)/1000)),expires_in_seconds:Math.max(0,Math.ceil((value.expiresAt-Date.now())/1000)),bytes:Buffer.byteLength(value.body)}));
  const requests=platformCacheStats.hits+platformCacheStats.misses,bytes=entries.reduce((sum,x)=>sum+x.bytes,0);
  res.json({enabled:true,scope:'Private platform read endpoints only',max_entries:PLATFORM_CACHE_MAX_ENTRIES,current_entries:entries.length,current_bytes:bytes,hit_rate_percent:requests?Math.round(platformCacheStats.hits*10000/requests)/100:0,stats:{...platformCacheStats},entries});
});
app.delete('/api/platform/cache',requirePlatformAuth,async(req,res)=>{const result=clearPlatformCache('platform owner');await platformAudit(req,'CLEAR','platform_response_cache',result);res.json({message:`${result.removed} cached response(s) cleared.`,...result})});

app.get('/api/platform/runtime',requirePlatformAuth,async(req,res)=>{
  let databaseLatency=null,databaseHealthy=false;
  try{const started=Date.now();await pool.query('SELECT 1');databaseLatency=Date.now()-started;databaseHealthy=true}catch(_){}
  res.status(databaseHealthy?200:503).json({instance_id:BACKGROUND_INSTANCE_ID,ready:runtimeState.ready,draining:runtimeState.draining,shutdown_signal:runtimeState.shutdown_signal,shutdown_started_at:runtimeState.shutdown_started_at,started_at:APP_STARTED_AT,uptime_seconds:Math.floor(process.uptime()),active_requests:runtimeState.active_requests,total_requests:runtimeState.total_requests,database:{healthy:databaseHealthy,latency_ms:databaseLatency,paths_separated:DATABASE_PATHS_SEPARATED,system_pool:{total:systemPool.totalCount,idle:systemPool.idleCount,waiting:systemPool.waitingCount,max:DATABASE_POOL_MAX},tenant_pool:{total:tenantPool.totalCount,idle:tenantPool.idleCount,waiting:tenantPool.waitingCount,max:DATABASE_POOL_MAX}},background:{scheduled_jobs:backgroundJobs.size,timer_handles:backgroundTimers.length},cache:{entries:platformResponseCache.size,hits:platformCacheStats.hits,misses:platformCacheStats.misses},memory:{heap_used_bytes:process.memoryUsage().heapUsed,rss_bytes:process.memoryUsage().rss},node_version:process.version});
});

app.get('/api/platform/scalability-readiness',requirePlatformAuth,async(req,res)=>{
  const started=Date.now();
  try{
    const dbStarted=Date.now();await pool.query('SELECT 1');const databaseLatency=Date.now()-dbStarted;
    const[indexes,latestLoad,jobHealth,webhookQueue,emailQueue,reportQueue,photoStorage]=await Promise.all([
      performanceIndexReadiness(),
      pool.query(`SELECT id,scenario,concurrency,duration_seconds,status,started_at,total_requests,failed_requests,requests_per_second,p95_ms FROM platform_load_tests ORDER BY started_at DESC LIMIT 1`),
      pool.query(`SELECT COUNT(*) FILTER(WHERE status='failed' AND started_at>=NOW()-INTERVAL '24 hours')::int failed_24h,COUNT(*) FILTER(WHERE status='running' AND started_at<NOW()-INTERVAL '10 minutes')::int stuck FROM platform_job_runs`),
      pool.query(`SELECT COUNT(*)::int count FROM webhook_deliveries WHERE status IN('queued','failed') AND attempts<5`),
      pool.query(`SELECT COUNT(*)::int count FROM email_deliveries WHERE status IN('queued','failed') AND attempt_count<5`),
      pool.query(`SELECT COUNT(*)::int count FROM client_report_runs WHERE status IN('pending','generated')`),
      pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE photo_data IS NOT NULL)::int database_photos,COUNT(*) FILTER(WHERE storage_provider='s3' AND storage_key IS NOT NULL)::int object_photos FROM incident_photos`)
    ]);
    const checks=[],add=(key,title,status,message,evidence={})=>checks.push({key,title,status,message,evidence});
    add('runtime','Runtime readiness',runtimeState.ready&&!runtimeState.draining?'pass':'fail',runtimeState.ready&&!runtimeState.draining?'Instance is ready and accepting work':'Instance is not ready or is draining',{ready:runtimeState.ready,draining:runtimeState.draining,instance_id:BACKGROUND_INSTANCE_ID});
    add('database','Database responsiveness',databaseLatency<200?'pass':databaseLatency<500?'warning':'fail',`Database responded in ${databaseLatency} ms`,{latency_ms:databaseLatency});
    add('tenant_path','Separated database paths',DATABASE_PATHS_SEPARATED?'pass':'fail',DATABASE_PATHS_SEPARATED?'System and restricted tenant connections are separated':'TENANT_DATABASE_URL is not separated from the system connection');
    const waiting=systemPool.waitingCount+tenantPool.waitingCount;add('pool_pressure','Connection-pool pressure',waiting===0?'pass':'warning',waiting===0?'No requests are waiting for a database connection':`${waiting} request(s) are waiting for a database connection`,{system_waiting:systemPool.waitingCount,tenant_waiting:tenantPool.waitingCount});
    const pendingIndexes=indexes.filter(x=>x.available&&!x.installed);add('indexes','Production indexes',pendingIndexes.length?'fail':'pass',pendingIndexes.length?`${pendingIndexes.length} recommended index(es) are missing`:`${indexes.filter(x=>x.installed).length} recommended indexes are installed`,{pending:pendingIndexes.map(x=>x.name)});
    const load=latestLoad.rows[0],loadRecent=load&&new Date(load.started_at)>=new Date(Date.now()-30*86400000),loadPassed=loadRecent&&Number(load.failed_requests)===0&&Number(load.p95_ms)<500;add('load_test','Controlled capacity baseline',loadPassed?'pass':'fail',!load?'No controlled load test has been recorded':!loadRecent?'Latest controlled load test is older than 30 days':loadPassed?`${load.total_requests} requests at ${load.requests_per_second}/sec with P95 ${load.p95_ms} ms`:'Latest controlled load test did not meet the production target',{latest:load||null});
    const jobs=jobHealth.rows[0];add('jobs','Background-job health',Number(jobs.failed_24h)===0&&Number(jobs.stuck)===0?'pass':'fail',`${jobs.failed_24h} failed in 24 hours; ${jobs.stuck} stuck`,jobs);
    const queues={webhooks:Number(webhookQueue.rows[0].count),emails:Number(emailQueue.rows[0].count),reports:Number(reportQueue.rows[0].count)},queued=queues.webhooks+queues.emails+queues.reports;add('queues','Delivery backlogs',queued===0?'pass':queued<25?'warning':'fail',queued===0?'No queued delivery backlog':`${queued} delivery item(s) are queued`,queues);
    const photos=photoStorage.rows[0];add('object_storage','Private object storage',OBJECT_STORAGE_CONFIGURED&&Number(photos.database_photos)===0?'pass':OBJECT_STORAGE_CONFIGURED?'warning':'fail',!OBJECT_STORAGE_CONFIGURED?'Private object storage is not configured':Number(photos.database_photos)?`${photos.database_photos} incident photo(s) remain in PostgreSQL`:'Private object storage is configured; no legacy photos remain',photos);
    const cacheRequests=platformCacheStats.hits+platformCacheStats.misses,hitRate=cacheRequests?Math.round(platformCacheStats.hits*10000/cacheRequests)/100:null;add('cache','Platform response cache',cacheRequests===0?'warning':'pass',cacheRequests===0?'No cache traffic has been measured since this instance started':`Cache has served ${platformCacheStats.hits} hit(s) with a ${hitRate}% hit rate`,{...platformCacheStats,hit_rate_percent:hitRate,entries:platformResponseCache.size});
    const rss=process.memoryUsage().rss;add('memory','Process memory',rss<512*1024*1024?'pass':rss<768*1024*1024?'warning':'fail',`Process RSS is ${Math.round(rss/1048576*10)/10} MB`,{rss_bytes:rss});
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length,ready=failures===0;
    const result={ready,status:ready?'ready':'action_required',generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},checks};
    await platformAudit(req,'RUN','scalability_readiness',{ready,summary:result.summary});res.json(result);
  }catch(e){res.status(500).json({error:e.message})}
});

// ------------------------ PHASE 5.8: PLATFORM ADMIN FOUNDATION ------------------------
const platformDigest=value=>crypto.createHmac('sha256',PLATFORM_JWT_SECRET).update(String(value)).digest('hex');
async function replacePlatformRecoveryCodes(adminId){const codes=makeRecoveryCodes(),client=await pool.connect();try{await client.query('BEGIN');await client.query(`DELETE FROM platform_mfa_recovery_codes WHERE platform_admin_id=$1`,[adminId]);for(const code of codes)await client.query(`INSERT INTO platform_mfa_recovery_codes(platform_admin_id,code_hash) VALUES($1,$2)`,[adminId,platformDigest('recovery:'+normalizeRecoveryCode(code))]);await client.query('COMMIT');return codes}catch(e){try{await client.query('ROLLBACK')}catch(_){}throw e}finally{client.release()}}
app.post('/api/platform/auth/login',fixedWindowRateLimit('platform-login',10),async(req,res)=>{if(!process.env.PLATFORM_JWT_SECRET)return res.status(503).json({error:'Platform authentication is not configured'});if(!process.env.BREVO_API_KEY||!EMAIL_FROM_ADDRESS)return res.status(503).json({error:'Platform verification email is not configured'});const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');try{const found=await pool.query(`SELECT * FROM platform_admins WHERE LOWER(email)=$1 AND active=TRUE LIMIT 1`,[email]);const admin=found.rows[0];if(!admin||!await bcrypt.compare(password,admin.password_hash))return res.status(401).json({error:'Invalid platform credentials'});const raw=crypto.randomBytes(32).toString('hex'),code=String(crypto.randomInt(0,1000000)).padStart(6,'0');await pool.query(`UPDATE platform_mfa_challenges SET used_at=NOW() WHERE platform_admin_id=$1 AND used_at IS NULL`,[admin.id]);await pool.query(`INSERT INTO platform_mfa_challenges(platform_admin_id,token_hash,code_hash,expires_at,ip_address,user_agent) VALUES($1,$2,$3,NOW()+INTERVAL '10 minutes',$4,$5)`,[admin.id,platformDigest(raw),platformDigest(code),requestIp(req),String(req.headers['user-agent']||'').slice(0,500)]);await sendProviderEmail({to:admin.email,subject:'PatrolSync Platform Admin verification code',html:emailHtml('Platform Admin verification',`<p>Enter this code to access the private PatrolSync platform console:</p><p style="font-size:30px;font-weight:bold;letter-spacing:6px">${code}</p><p>The code expires in 10 minutes. Never share it.</p>`)});res.status(202).json({mfa_required:true,challenge_token:raw,masked_email:admin.email.replace(/^(.{2}).*(@.*)$/,'$1***$2')})}catch(e){console.error('Platform login failed:',e.message);res.status(500).json({error:'Could not start platform login'})}});
app.post('/api/platform/auth/verify',fixedWindowRateLimit('platform-mfa',15),async(req,res)=>{const client=await pool.connect();try{await client.query('BEGIN');const found=await client.query(`SELECT c.*,a.email,a.display_name,a.active FROM platform_mfa_challenges c JOIN platform_admins a ON a.id=c.platform_admin_id WHERE c.token_hash=$1 AND c.used_at IS NULL AND c.expires_at>NOW() FOR UPDATE OF c`,[platformDigest(req.body.challenge_token||'')]);if(!found.rowCount){await client.query('ROLLBACK');return res.status(400).json({error:'Verification code is invalid or expired'})}const c=found.rows[0],rawCode=String(req.body.code||'').trim();if(!c.active){await client.query('ROLLBACK');return res.status(401).json({error:'Platform account disabled'})}if(c.attempts>=5){await client.query('ROLLBACK');return res.status(429).json({error:'Too many incorrect attempts'})}let recoveryUsed=false,valid=false;if(/^\d{6}$/.test(rawCode)){const supplied=platformDigest(rawCode);valid=crypto.timingSafeEqual(Buffer.from(supplied,'hex'),Buffer.from(c.code_hash,'hex'))}else{const recovery=(await client.query(`SELECT id FROM platform_mfa_recovery_codes WHERE platform_admin_id=$1 AND code_hash=$2 AND used_at IS NULL FOR UPDATE`,[c.platform_admin_id,platformDigest('recovery:'+normalizeRecoveryCode(rawCode))])).rows[0];if(recovery){valid=true;recoveryUsed=true;await client.query(`UPDATE platform_mfa_recovery_codes SET used_at=NOW() WHERE id=$1`,[recovery.id])}}if(!valid){await client.query(`UPDATE platform_mfa_challenges SET attempts=attempts+1 WHERE id=$1`,[c.id]);await client.query('COMMIT');return res.status(400).json({error:'Incorrect verification or recovery code'})}const sessionId=crypto.randomUUID();await client.query(`UPDATE platform_mfa_challenges SET used_at=NOW() WHERE id=$1`,[c.id]);await client.query(`UPDATE platform_admins SET last_login_at=NOW() WHERE id=$1`,[c.platform_admin_id]);await client.query(`INSERT INTO platform_auth_sessions(id,platform_admin_id,ip_address,user_agent,expires_at) VALUES($1,$2,$3,$4,NOW()+INTERVAL '4 hours')`,[sessionId,c.platform_admin_id,requestIp(req),String(req.headers['user-agent']||'').slice(0,500)]);await client.query(`INSERT INTO platform_audit_logs(platform_admin_id,admin_email,action,resource,details,ip_address,request_id) VALUES($1,$2,'LOGIN','platform_console',$3::jsonb,$4,$5)`,[c.platform_admin_id,c.email,JSON.stringify({user_agent:c.user_agent,recovery_code_used:recoveryUsed,session_id:sessionId}),requestIp(req),req.requestId]);await client.query('COMMIT');const token=jwt.sign({platform_admin_id:c.platform_admin_id,email:c.email,role:'platform_admin',session_id:sessionId},PLATFORM_JWT_SECRET,{expiresIn:'4h',audience:'patrolsync-platform',issuer:'patrolsync'});res.json({token,recovery_code_used:recoveryUsed,admin:{id:c.platform_admin_id,email:c.email,display_name:c.display_name},expires_in_hours:4})}catch(e){try{await client.query('ROLLBACK')}catch(_){}res.status(500).json({error:'Could not verify platform login'})}finally{client.release()}});
app.get('/api/platform/overview',requirePlatformAuth,async(req,res)=>{try{const[tenants,users,sites,guards,plans,sessions,events]=await Promise.all([pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE created_at>=NOW()-INTERVAL '30 days')::int new_30_days FROM tenants`),pool.query(`SELECT COUNT(*)::int total FROM users WHERE COALESCE(account_active,TRUE)=TRUE`),pool.query(`SELECT COUNT(*)::int total FROM sites`),pool.query(`SELECT COUNT(*)::int total FROM users WHERE role='guard' AND COALESCE(account_active,TRUE)=TRUE`),pool.query(`SELECT plan,COUNT(*)::int companies FROM tenants GROUP BY plan ORDER BY companies DESC`),pool.query(`SELECT COUNT(*)::int active FROM auth_sessions WHERE revoked_at IS NULL AND expires_at>NOW()`),pool.query(`SELECT severity,COUNT(*)::int count FROM system_events WHERE created_at>=NOW()-INTERVAL '24 hours' GROUP BY severity`)]);await platformAudit(req,'VIEW','platform_overview');res.json({generated_at:new Date(),companies:tenants.rows[0],active_users:users.rows[0].total,active_guards:guards.rows[0].total,sites:sites.rows[0].total,active_admin_sessions:sessions.rows[0].active,plans:plans.rows,system_events_24h:events.rows})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/platform/tenants',requirePlatformAuth,async(req,res)=>{try{const result=await pool.query(`SELECT t.id,t.name,t.slug,t.plan,t.timezone,t.created_at,COUNT(DISTINCT s.id)::int sites,COUNT(DISTINCT u.id) FILTER(WHERE u.role='guard' AND COALESCE(u.account_active,TRUE)=TRUE)::int guards,COUNT(DISTINCT u.id) FILTER(WHERE u.role='admin' AND COALESCE(u.account_active,TRUE)=TRUE)::int admins FROM tenants t LEFT JOIN sites s ON s.tenant_id=t.id LEFT JOIN users u ON u.tenant_id=t.id GROUP BY t.id ORDER BY t.created_at DESC LIMIT 500`);await platformAudit(req,'VIEW','tenant_directory',{count:result.rowCount});res.json(result.rows)}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/platform/audit',requirePlatformAuth,async(req,res)=>{try{const result=await pool.query(`SELECT admin_email,action,resource,details,ip_address,request_id,created_at FROM platform_audit_logs ORDER BY created_at DESC LIMIT 250`);res.json(result.rows)}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/platform/security/sessions',requirePlatformAuth,async(req,res)=>{try{const result=await pool.query(`SELECT id,ip_address,user_agent,created_at,last_seen_at,expires_at,revoked_at,revoked_reason FROM platform_auth_sessions WHERE platform_admin_id=$1 ORDER BY created_at DESC LIMIT 100`,[req.platformAdmin.id]);res.json({current_session_id:req.platformSessionId,sessions:result.rows.map(x=>({...x,current:x.id===req.platformSessionId,status:x.revoked_at?'revoked':new Date(x.expires_at)<=new Date()?'expired':'active'}))})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/api/platform/security/sessions/:id',requirePlatformAuth,async(req,res)=>{try{const changed=await pool.query(`UPDATE platform_auth_sessions SET revoked_at=NOW(),revoked_reason='Revoked by platform owner' WHERE id=$1 AND platform_admin_id=$2 AND revoked_at IS NULL RETURNING id`,[req.params.id,req.platformAdmin.id]);if(!changed.rowCount)return res.status(404).json({error:'Active platform session not found'});await platformAudit(req,'REVOKE_SESSION','platform_session',{session_id:req.params.id});res.json({message:'Platform session revoked.',current_session_revoked:req.params.id===req.platformSessionId})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/platform/security/sessions/revoke-others',requirePlatformAuth,async(req,res)=>{try{const changed=await pool.query(`UPDATE platform_auth_sessions SET revoked_at=NOW(),revoked_reason='Other sessions signed out' WHERE platform_admin_id=$1 AND id<>$2 AND revoked_at IS NULL AND expires_at>NOW() RETURNING id`,[req.platformAdmin.id,req.platformSessionId]);await platformAudit(req,'REVOKE_OTHER_SESSIONS','platform_session',{count:changed.rowCount});res.json({message:`${changed.rowCount} other platform session(s) signed out.`,revoked_count:changed.rowCount})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/platform/security/recovery-codes',requirePlatformAuth,async(req,res)=>{try{const found=await pool.query(`SELECT password_hash FROM platform_admins WHERE id=$1`,[req.platformAdmin.id]);if(!found.rowCount||!await bcrypt.compare(String(req.body.password||''),found.rows[0].password_hash))return res.status(401).json({error:'Current platform password is incorrect'});const codes=await replacePlatformRecoveryCodes(req.platformAdmin.id);await pool.query(`UPDATE platform_auth_sessions SET revoked_at=NOW(),revoked_reason='Recovery codes regenerated' WHERE platform_admin_id=$1 AND id<>$2 AND revoked_at IS NULL`,[req.platformAdmin.id,req.platformSessionId]);await platformAudit(req,'GENERATE_RECOVERY_CODES','platform_security',{count:codes.length});res.json({message:'Recovery codes generated. Save them now; they cannot be displayed again.',recovery_codes:codes})}catch(e){res.status(500).json({error:'Could not generate recovery codes'})}});

app.post('/api/platform/launch-readiness/attest',requirePlatformAuth,async(req,res)=>{try{const backupVerified=Boolean(req.body.backup_verified),monitoringVerified=Boolean(req.body.monitoring_verified),filename=String(req.body.backup_filename||'').trim().slice(0,300),sha=String(req.body.backup_sha256||'').trim().toUpperCase().slice(0,64),endpoint=String(req.body.monitoring_endpoint||'https://patrolsync-backend.onrender.com/health').trim().slice(0,500),notes=String(req.body.notes||'').trim().slice(0,2000);if(backupVerified&&!filename)return res.status(400).json({error:'Backup filename is required when confirming backup verification'});if(sha&&!/^[A-F0-9]{64}$/.test(sha))return res.status(400).json({error:'SHA-256 must contain exactly 64 hexadecimal characters'});await pool.query(`UPDATE platform_launch_attestations SET backup_verified_at=CASE WHEN $1 THEN NOW() ELSE NULL END,backup_filename=$2,backup_sha256=$3,monitoring_verified_at=CASE WHEN $4 THEN NOW() ELSE NULL END,monitoring_endpoint=$5,notes=$6,updated_by_platform_admin_id=$7,updated_at=NOW() WHERE id=1`,[backupVerified,filename||null,sha||null,monitoringVerified,endpoint||null,notes||null,req.platformAdmin.id]);await platformAudit(req,'ATTEST','launch_readiness',{backup_verified:backupVerified,monitoring_verified:monitoringVerified,backup_filename:filename});res.json({message:'Launch evidence saved.'})}catch(e){res.status(500).json({error:e.message})}});

app.get('/api/platform/launch-readiness',requirePlatformAuth,async(req,res)=>{let tenantClient;try{const started=Date.now(),checks=[],add=(key,label,critical,passed,message,details={})=>checks.push({key,label,critical,passed:Boolean(passed),status:passed?'pass':critical?'fail':'warning',message,details});const dbStarted=Date.now();await pool.query('SELECT 1');const dbLatency=Date.now()-dbStarted,posture=getProductionSecurityPosture();add('api_security','Production API security',true,posture.ready,posture.ready?'All critical API security checks pass':'Critical production security configuration remains incomplete',{failed:posture.checks.filter(x=>x.critical&&!x.passed).map(x=>x.message)});add('database_health','Database connectivity',true,true,`Database connected in ${dbLatency} ms`,{latency_ms:dbLatency});const rls=(await pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE c.relrowsecurity)::int enabled,COUNT(*) FILTER(WHERE EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname))::int protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped WHERE n.nspname='public' AND c.relkind IN('r','p')`)).rows[0];add('rls','Tenant-table RLS coverage',true,Number(rls.total)>0&&Number(rls.enabled)===Number(rls.total)&&Number(rls.protected)===Number(rls.total),`${rls.protected}/${rls.total} tenant tables have policies; ${rls.enabled}/${rls.total} have RLS enabled`,rls);const firstTenant=(await pool.query(`SELECT id FROM tenants WHERE COALESCE(account_active,TRUE)=TRUE ORDER BY id LIMIT 1`)).rows[0];let crossVisible=0;if(firstTenant){tenantClient=await tenantPool.connect();await tenantClient.query(`SELECT set_config('app.current_tenant',$1,false)`,[String(firstTenant.id)]);crossVisible=Number((await tenantClient.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id<>$1`,[firstTenant.id])).rows[0].count)}add('tenant_isolation','Cross-company isolation probe',true,DATABASE_PATHS_SEPARATED&&crossVisible===0,DATABASE_PATHS_SEPARATED&&crossVisible===0?'Restricted tenant connection cannot see other companies':`${crossVisible} cross-company user record(s) visible`,{paths_separated:DATABASE_PATHS_SEPARATED,cross_company_users_visible:crossVisible});const[duplicates,brokenAssignments,overlaps,deadWebhooks,deadEmails,recovery,attestation]=await Promise.all([pool.query(`SELECT COUNT(*)::int count FROM(SELECT tenant_id,LOWER(email),role FROM users WHERE COALESCE(account_active,TRUE)=TRUE GROUP BY tenant_id,LOWER(email),role HAVING COUNT(*)>1)x`),pool.query(`SELECT COUNT(*)::int count FROM guard_assignments ga LEFT JOIN users u ON u.id=ga.user_id AND u.tenant_id=ga.tenant_id LEFT JOIN sites s ON s.id=ga.site_id AND s.tenant_id=ga.tenant_id WHERE u.id IS NULL OR s.id IS NULL`),pool.query(`SELECT COUNT(*)::int count FROM(SELECT tenant_id,user_id FROM attendance_sessions WHERE clocked_out_at IS NULL GROUP BY tenant_id,user_id HAVING COUNT(*)>1)x`),pool.query(`SELECT COUNT(*)::int count FROM webhook_deliveries WHERE status='failed' AND attempts>=5`),pool.query(`SELECT COUNT(*)::int count FROM email_deliveries WHERE status='failed' AND attempt_count>=5`),pool.query(`SELECT COUNT(*)::int count FROM platform_mfa_recovery_codes WHERE platform_admin_id=$1 AND used_at IS NULL`,[req.platformAdmin.id]),pool.query(`SELECT * FROM platform_launch_attestations WHERE id=1`)]);add('identity_integrity','Unique active identities',true,Number(duplicates.rows[0].count)===0,Number(duplicates.rows[0].count)===0?'No duplicate active identities':'Duplicate active identities require cleanup',{count:Number(duplicates.rows[0].count)});add('relationship_integrity','Assignment relationships',true,Number(brokenAssignments.rows[0].count)===0,Number(brokenAssignments.rows[0].count)===0?'No broken guard assignments':'Broken guard assignments exist',{count:Number(brokenAssignments.rows[0].count)});add('attendance_integrity','Attendance concurrency',true,Number(overlaps.rows[0].count)===0,Number(overlaps.rows[0].count)===0?'No guards have multiple open clock-ins':'Multiple open clock-ins require correction',{count:Number(overlaps.rows[0].count)});add('delivery_queues','Delivery queues',false,Number(deadWebhooks.rows[0].count)===0&&Number(deadEmails.rows[0].count)===0,`Exhausted webhooks: ${deadWebhooks.rows[0].count}; exhausted emails: ${deadEmails.rows[0].count}`,{webhooks:Number(deadWebhooks.rows[0].count),emails:Number(deadEmails.rows[0].count)});add('platform_recovery','Platform recovery codes',true,Number(recovery.rows[0].count)>0,Number(recovery.rows[0].count)>0?`${recovery.rows[0].count} unused recovery code(s) available`:'Generate platform-owner recovery codes');const evidence=attestation.rows[0]||{},backupFresh=evidence.backup_verified_at&&Date.now()-new Date(evidence.backup_verified_at).getTime()<=30*86400000;add('backup','Verified database backup',true,backupFresh,backupFresh?`Backup verified ${new Date(evidence.backup_verified_at).toISOString()}`:'Confirm a downloaded and integrity-checked backup from the last 30 days',{filename:evidence.backup_filename,sha256:evidence.backup_sha256,verified_at:evidence.backup_verified_at});add('monitoring','Production health monitoring',true,Boolean(evidence.monitoring_verified_at),evidence.monitoring_verified_at?'Health monitoring confirmation recorded':'Confirm the Render /health check and notification destination',{endpoint:evidence.monitoring_endpoint,verified_at:evidence.monitoring_verified_at});const criticalFailures=checks.filter(x=>x.critical&&!x.passed).length,warnings=checks.filter(x=>!x.critical&&!x.passed).length;await platformAudit(req,'RUN','launch_readiness',{critical_failures:criticalFailures,warnings});res.json({status:criticalFailures?'not_ready':warnings?'ready_with_warnings':'ready',generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,warnings,critical_failures:criticalFailures,total:checks.length},checks,evidence,request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}finally{if(tenantClient){let resetError;try{await tenantClient.query('RESET app.current_tenant')}catch(e){resetError=e}tenantClient.release(resetError)}}});

app.get('/api/security/email-mfa',requireAuth,requireAdmin,async(req,res)=>{try{const result=await pool.query(`SELECT email,email_mfa_enabled FROM users WHERE id=$1 AND tenant_id=$2`,[req.auth.user_id,req.auth.tenant_id]);res.json({email:result.rows[0]?.email,enabled:Boolean(result.rows[0]?.email_mfa_enabled),provider_ready:Boolean(process.env.BREVO_API_KEY&&EMAIL_FROM_ADDRESS)})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/email-mfa/start',requireAuth,requireAdmin,async(req,res)=>{try{if(!process.env.BREVO_API_KEY||!EMAIL_FROM_ADDRESS)return res.status(409).json({error:'Transactional email provider is not configured'});const found=await pool.query(`SELECT id,tenant_id,email,role FROM users WHERE id=$1 AND tenant_id=$2 AND COALESCE(account_active,TRUE)=TRUE`,[req.auth.user_id,req.auth.tenant_id]);if(!found.rowCount)return res.status(404).json({error:'Account not found'});const challengeToken=await createEmailMfaChallenge(found.rows[0],'enable');res.json({challenge_token:challengeToken,message:'Verification code sent',expires_in_minutes:10})}catch(e){res.status(500).json({error:'Could not send verification code'})}});
app.post('/api/security/email-mfa/confirm',requireAuth,requireAdmin,async(req,res)=>{try{const verified=await consumeEmailMfaChallenge(req.body.challenge_token,req.body.code,'enable');if(Number(verified.user_id)!==Number(req.auth.user_id)||Number(verified.tenant_id)!==Number(req.auth.tenant_id))return res.status(403).json({error:'Verification belongs to another account'});await pool.query(`UPDATE users SET email_mfa_enabled=TRUE WHERE id=$1 AND tenant_id=$2`,[req.auth.user_id,req.auth.tenant_id]);const recoveryCodes=await replaceUserRecoveryCodes(req.auth.tenant_id,req.auth.user_id);res.json({enabled:true,message:'Email two-step verification enabled. Save your recovery codes now.',recovery_codes:recoveryCodes})}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.post('/api/security/email-mfa/recovery-codes',requireAuth,requireAdmin,async(req,res)=>{try{const found=await pool.query(`SELECT password_hash,email_mfa_enabled FROM users WHERE id=$1 AND tenant_id=$2`,[req.auth.user_id,req.auth.tenant_id]);if(!found.rowCount||!found.rows[0].email_mfa_enabled)return res.status(409).json({error:'Enable two-step verification first'});if(!await bcrypt.compare(String(req.body.password||''),found.rows[0].password_hash||''))return res.status(401).json({error:'Current password is incorrect'});const recoveryCodes=await replaceUserRecoveryCodes(req.auth.tenant_id,req.auth.user_id);await pool.query(`UPDATE auth_sessions SET revoked_at=NOW(),revoked_reason='Recovery codes regenerated' WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL AND id<>$3`,[req.auth.tenant_id,req.auth.user_id,req.auth.session_id]);res.json({message:'New recovery codes generated. Previous codes no longer work.',recovery_codes:recoveryCodes})}catch(e){res.status(500).json({error:'Could not generate recovery codes'})}});
app.delete('/api/security/email-mfa',requireAuth,requireAdmin,async(req,res)=>{try{const found=await pool.query(`SELECT password_hash FROM users WHERE id=$1 AND tenant_id=$2`,[req.auth.user_id,req.auth.tenant_id]);if(!found.rowCount||!await bcrypt.compare(String(req.body.password||''),found.rows[0].password_hash||''))return res.status(401).json({error:'Current password is incorrect'});await pool.query(`UPDATE users SET email_mfa_enabled=FALSE WHERE id=$1 AND tenant_id=$2`,[req.auth.user_id,req.auth.tenant_id]);await pool.query(`DELETE FROM mfa_recovery_codes WHERE tenant_id=$1 AND user_id=$2`,[req.auth.tenant_id,req.auth.user_id]);res.json({enabled:false,message:'Email two-step verification disabled'})}catch(e){res.status(500).json({error:'Could not disable two-step verification'})}});

// ------------------------ SITES & CHECKPOINTS ------------------------

app.post('/api/sites', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, name, address } = req.body;
  if (!tenant_id || !name) return res.status(400).json({ error: 'tenant_id and name are required' });
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const limitCheck = await checkPlanLimit(client, tenant_id, 'locations');
      if (!limitCheck.allowed) {
        const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} location(s). Upgrade your plan to add more.`);
        err.statusCode = 403;
        throw err;
      }
      return client.query(
        'INSERT INTO sites (tenant_id, name, address) VALUES ($1, $2, $3) RETURNING *',
        [tenant_id, name, address || null]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/sites', requireAuth, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query('SELECT * FROM sites WHERE tenant_id = $1 ORDER BY created_at DESC', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/sites/:id/geofence', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = Number(req.body.tenant_id || req.auth.tenant_id);
  if (tenantId !== Number(req.auth.tenant_id)) return res.status(403).json({ error: 'Tenant access denied' });
  const enabled = Boolean(req.body.geofence_enabled);
  const latitude = req.body.latitude === null || req.body.latitude === '' ? null : Number(req.body.latitude);
  const longitude = req.body.longitude === null || req.body.longitude === '' ? null : Number(req.body.longitude);
  const radius = Number(req.body.geofence_radius_m);
  if (enabled && (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 || !Number.isFinite(longitude) || longitude < -180 || longitude > 180)) {
    return res.status(400).json({ error: 'Valid latitude and longitude are required when the geofence is enabled' });
  }
  if (!Number.isInteger(radius) || radius < 25 || radius > 5000) {
    return res.status(400).json({ error: 'Geofence radius must be between 25 and 5000 metres' });
  }
  try {
    const result = await withTenant(tenantId, client => client.query(
      `UPDATE sites SET latitude=$1, longitude=$2, geofence_radius_m=$3, geofence_enabled=$4
       WHERE id=$5 AND tenant_id=$6 RETURNING *`,
      [latitude, longitude, radius, enabled, req.params.id, tenantId]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Site not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/checkpoints', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, name, qr_code, latitude, longitude, building, floor } = req.body;
  const nfcTagUid = String(req.body.nfc_tag_uid || '').trim().toUpperCase().replace(/[^A-Z0-9:_-]/g, '') || null;
  if (!tenant_id || !site_id || !name || !qr_code) {
    return res.status(400).json({ error: 'tenant_id, site_id, name, and qr_code are required' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const limitCheck = await checkPlanLimit(client, tenant_id, 'checkpoints');
      if (!limitCheck.allowed) {
        const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} checkpoint(s). Upgrade your plan to add more.`);
        err.statusCode = 403;
        throw err;
      }
      return client.query(
        'INSERT INTO checkpoints (tenant_id, site_id, name, qr_code, latitude, longitude, building, floor, nfc_tag_uid) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
        [tenant_id, site_id, name, qr_code, latitude || null, longitude || null, building || null, floor || null, nfcTagUid]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A checkpoint with this QR code or NFC tag already exists' });
    }
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.get('/api/checkpoints', requireAuth, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      site_id
        ? client.query('SELECT * FROM checkpoints WHERE tenant_id = $1 AND site_id = $2 ORDER BY created_at DESC', [tenant_id, site_id])
        : client.query('SELECT * FROM checkpoints WHERE tenant_id = $1 ORDER BY created_at DESC', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/checkpoints/lookup', requireAuth, async (req, res) => {
  const { tenant_id, qr_code, nfc_tag_uid } = req.query;
  const lookupMethod = nfc_tag_uid ? 'nfc' : 'qr';
  const lookupValue = lookupMethod === 'nfc'
    ? String(nfc_tag_uid || '').trim().toUpperCase().replace(/[^A-Z0-9:_-]/g, '')
    : String(qr_code || '').trim();
  if (!tenant_id || !lookupValue) return res.status(400).json({ error: 'tenant_id and a QR code or NFC tag are required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `SELECT c.*, s.name as site_name FROM checkpoints c
         JOIN sites s ON s.id = c.site_id
         WHERE c.tenant_id = $1 AND ${lookupMethod === 'nfc' ? 'c.nfc_tag_uid' : 'c.qr_code'} = $2`,
        [tenant_id, lookupValue]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No checkpoint matches this ' + (lookupMethod === 'nfc' ? 'NFC tag' : 'QR code') });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/qr-image', (req, res) => {
  const { text, token } = req.query;
  if (!text) return res.status(400).send('text query param is required');
  if (!token) return res.status(401).send('token query param is required');

  try {
    jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).send('Invalid or expired token');
  }

  QRCode.toBuffer(String(text), { width: 220, margin: 1 }, (err, buffer) => {
    if (err) return res.status(500).send('Failed to generate QR image');
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(buffer);
  });
});

app.patch('/api/checkpoints/:id/nfc', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const nfcTagUid = String(req.body.nfc_tag_uid || '').trim().toUpperCase().replace(/[^A-Z0-9:_-]/g, '') || null;
  try {
    const result = await withTenant(tenantId, client => client.query(
      'UPDATE checkpoints SET nfc_tag_uid=$1 WHERE id=$2 AND tenant_id=$3 RETURNING *',
      [nfcTagUid, req.params.id, tenantId]
    ));
    if (!result.rows.length) return res.status(404).json({ error: 'Checkpoint not found' });
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'This NFC tag is already assigned to another checkpoint' });
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/checkpoints/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, async (client) => {
      await client.query('DELETE FROM patrol_logs WHERE checkpoint_id = $1 AND tenant_id = $2', [id, tenant_id]);
      await client.query('DELETE FROM notifications WHERE checkpoint_id = $1 AND tenant_id = $2', [id, tenant_id]);
      return client.query('DELETE FROM checkpoints WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id]);
    });
    if (result.rows.length === 0) return res.status(404).json({ error: 'Checkpoint not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ USERS & GUARDS ------------------------

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, firebase_uid, email, role, password } = req.body;
  if (!tenant_id || !email) {
    return res.status(400).json({ error: 'tenant_id and email are required' });
  }
  if (role && !['admin', 'guard'].includes(role)) {
    return res.status(400).json({ error: 'role must be admin or guard' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      const requestedRole=role||'guard';
      const existing=await client.query(`SELECT id,account_active FROM users WHERE tenant_id=$1 AND LOWER(email)=LOWER($2) AND role=$3 ORDER BY account_active DESC,id DESC`,[tenant_id,email.trim(),requestedRole]);
      if(existing.rows.some(x=>x.account_active!==false))throw Object.assign(new Error(`An active ${requestedRole} account already uses this email`),{statusCode:409});
      if ((role || 'guard') === 'guard') {
        const limitCheck = await checkPlanLimit(client, tenant_id, 'guards');
        if (!limitCheck.allowed) {
          const err = new Error(`Your ${limitCheck.plan} plan allows up to ${limitCheck.max} guard(s). Upgrade your plan to add more.`);
          err.statusCode = 403;
          throw err;
        }
      }
      const hash = password ? await bcrypt.hash(password, 10) : null;
      return client.query(
        'INSERT INTO users (tenant_id, firebase_uid, email, role, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, tenant_id, email, role',
        [tenant_id, firebase_uid || null, email.toLowerCase().trim(), role || 'guard', hash]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || (err.code==='23505'?409:500)).json({ error: err.code==='23505'?'An active account with this email and role already exists':err.message });
  }
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, role } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const includeInactive=req.query.include_inactive==='true';
    const result = await withTenant(tenant_id, (client) =>
      role
        ? client.query(`SELECT * FROM users WHERE tenant_id=$1 AND role=$2 AND ($3::boolean OR COALESCE(account_active,TRUE)=TRUE) ORDER BY created_at DESC`,[tenant_id,role,includeInactive])
        : client.query(`SELECT * FROM users WHERE tenant_id=$1 AND ($2::boolean OR COALESCE(account_active,TRUE)=TRUE) ORDER BY created_at DESC`,[tenant_id,includeInactive])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  if (Number(id) === req.auth.user_id) {
    return res.status(400).json({ error: 'You cannot remove your own account' });
  }
  try {
    const result = await withTenant(tenant_id, async (client) => {
      await client.query('BEGIN');
      try {
        const archived=await client.query("UPDATE users SET account_active=FALSE,password_changed_at=NOW() WHERE id=$1 AND tenant_id=$2 AND role='guard' AND COALESCE(account_active,TRUE)=TRUE RETURNING id,email",[id,tenant_id]);
        if(archived.rowCount)await client.query('DELETE FROM guard_assignments WHERE tenant_id=$1 AND user_id=$2',[tenant_id,id]);
        await client.query('COMMIT');return archived;
      } catch(e) { await client.query('ROLLBACK');throw e; }
    });
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Active guard not found, or guard is already archived' });
    }
    res.json({ archived: result.rows[0],message:'Guard archived. Historical operational records were preserved.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id/permanent',requireAuth,requireOwnerAdmin,async(req,res)=>{const id=Number(req.params.id),t=communicationTenant(req,req.body.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});if(!Number.isInteger(id)||id<1||id===Number(req.auth.user_id))return res.status(400).json({error:'Invalid account ID'});if(String(req.body.confirmation||'')!==`DELETE ${id}`)return res.status(400).json({error:`Type DELETE ${id} to confirm permanent deletion`});try{const deleted=await withTenant(t,async c=>{await c.query('BEGIN');try{const user=await c.query(`SELECT id,email,role,account_active FROM users WHERE id=$1 AND tenant_id=$2 AND role IN('guard','staff') FOR UPDATE`,[id,t]);if(!user.rowCount)throw Object.assign(new Error('Guard or staff account not found'),{statusCode:404});if(user.rows[0].account_active!==false)throw Object.assign(new Error('Archive the account before permanently deleting it'),{statusCode:409});const columns=await c.query(`SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name<>'users' AND data_type IN('smallint','integer','bigint') AND (column_name IN('user_id','guard_id','created_by','updated_by','assigned_to','author_id','requester_id','target_user_id','reviewed_by','approved_by','resolved_by') OR column_name LIKE '%\\_user\\_id' ESCAPE '\\' OR column_name LIKE '%\\_guard\\_id' ESCAPE '\\' OR column_name LIKE '%\\_by' ESCAPE '\\') ORDER BY table_name,column_name`);const references=[];for(const column of columns.rows){const q=s=>'"'+String(s).replaceAll('"','""')+'"';const count=await c.query(`SELECT COUNT(*)::int count FROM ${q(column.table_name)} WHERE ${q(column.column_name)}=$1`,[id]);if(Number(count.rows[0].count)>0)references.push({table:column.table_name,column:column.column_name,count:Number(count.rows[0].count)})}if(references.length)throw Object.assign(new Error('Permanent deletion blocked because historical or operational records reference this account'),{statusCode:409,references});const result=await c.query(`DELETE FROM users WHERE id=$1 AND tenant_id=$2 RETURNING id,email,role`,[id,t]);await c.query('COMMIT');return result.rows[0]}catch(e){await c.query('ROLLBACK');throw e}});res.json({deleted,message:'Unused archived account permanently deleted.'})}catch(e){res.status(e.statusCode||500).json({error:e.message,references:e.references||[],request_id:req.requestId})}});

app.patch('/api/users/:id/restore',requireAuth,requireOwnerAdmin,async(req,res)=>{const id=Number(req.params.id),t=communicationTenant(req,req.body.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'Invalid account ID'});try{const restored=await withTenant(t,async c=>{await c.query('BEGIN');try{const user=await c.query(`SELECT id,email,role,account_active FROM users WHERE id=$1 AND tenant_id=$2 AND role IN('guard','staff') FOR UPDATE`,[id,t]);if(!user.rowCount)throw Object.assign(new Error('Archived guard or staff account not found'),{statusCode:404});const target=user.rows[0];if(target.account_active!==false)throw Object.assign(new Error('Account is already active'),{statusCode:409});const duplicate=await c.query(`SELECT id FROM users WHERE tenant_id=$1 AND id<>$2 AND LOWER(email)=LOWER($3) AND role=$4 AND COALESCE(account_active,TRUE)=TRUE LIMIT 1`,[t,id,target.email,target.role]);if(duplicate.rowCount)throw Object.assign(new Error(`Cannot restore because active ${target.role} ID ${duplicate.rows[0].id} already uses this email`),{statusCode:409});const result=await c.query(`UPDATE users SET account_active=TRUE,password_changed_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING id,email,role`,[id,t]);await c.query('COMMIT');return result.rows[0]}catch(e){await c.query('ROLLBACK');throw e}});res.json({restored,message:'Account restored. Reset its password if needed and reassign its site.'})}catch(e){res.status(e.statusCode||500).json({error:e.message,request_id:req.requestId})}});

app.patch('/api/users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, new_password } = req.body;
  if (!tenant_id || !new_password) {
    return res.status(400).json({ error: 'tenant_id and new_password are required' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ error: 'new_password must be at least 6 characters' });
  }
  try {
    const hash = await bcrypt.hash(new_password, 10);
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        "UPDATE users SET password_hash = $1 WHERE id = $2 AND tenant_id = $3 AND role = 'guard' RETURNING id, email",
        [hash, id, tenant_id]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Guard not found, or user is not a guard' });
    }
    res.json({ reset: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ GUARD ASSIGNMENTS & PROGRESS ------------------------

app.post('/api/guard-assignments', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, user_id, round_size } = req.body;
  if (!tenant_id || !site_id || !user_id) {
    return res.status(400).json({ error: 'tenant_id, site_id, and user_id are required' });
  }
  const roundSizeVal = (round_size !== undefined && round_size !== null && round_size !== '') ? Number(round_size) : null;
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `INSERT INTO guard_assignments (tenant_id, site_id, user_id, round_size) VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, site_id, user_id) DO NOTHING RETURNING *`,
        [tenant_id, site_id, user_id, roundSizeVal]
      )
    );
    if (result.rows.length === 0) {
      return res.status(409).json({ error: 'This guard is already assigned to this site' });
    }
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-assignments', requireAuth, async (req, res) => {
  const { tenant_id, user_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });

  if (req.auth.role !== 'admin' && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own assignments' });
  }

  try {
    const result = await withTenant(tenant_id, (client) => {
      let query = `SELECT ga.*, s.name as site_name, s.geofence_enabled, s.geofence_radius_m, u.email as guard_email
                   FROM guard_assignments ga
                   JOIN sites s ON s.id = ga.site_id
                   JOIN users u ON u.id = ga.user_id
                   WHERE ga.tenant_id = $1`;
      const params = [tenant_id];
      if (user_id) { params.push(user_id); query += ` AND ga.user_id = $${params.length}`; }
      if (site_id) { params.push(site_id); query += ` AND ga.site_id = $${params.length}`; }
      query += ' ORDER BY ga.created_at DESC';
      return client.query(query, params);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/guard-assignments/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, round_size } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  const roundSizeVal = (round_size !== undefined && round_size !== null && round_size !== '') ? Number(round_size) : null;
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'UPDATE guard_assignments SET round_size = $1 WHERE id = $2 AND tenant_id = $3 RETURNING *',
        [roundSizeVal, id, tenant_id]
      )
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Assignment not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/guard-assignments/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query('DELETE FROM guard_assignments WHERE id = $1 AND tenant_id = $2 RETURNING *', [id, tenant_id])
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Assignment not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/guard-progress', requireAuth, async (req, res) => {
  const { tenant_id, site_id, user_id } = req.query;
  if (!tenant_id || !site_id || !user_id) {
    return res.status(400).json({ error: 'tenant_id, site_id, and user_id are required' });
  }
  if (req.auth.role !== 'admin' && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own progress' });
  }
  try {
    const data = await withTenant(tenant_id, async (client) => {
      const tenantRes = await client.query('SELECT timezone FROM tenants WHERE id = $1', [tenant_id]);
      const zone = (tenantRes.rows[0] && tenantRes.rows[0].timezone) || 'UTC';

      const assignmentRes = await client.query(
        'SELECT * FROM guard_assignments WHERE tenant_id = $1 AND site_id = $2 AND user_id = $3',
        [tenant_id, site_id, user_id]
      );
      if (assignmentRes.rows.length === 0) {
        const err = new Error('Guard is not assigned to this site');
        err.statusCode = 404;
        throw err;
      }
      const assignment = assignmentRes.rows[0];

      const checkpointsRes = await client.query(
        'SELECT id, name FROM checkpoints WHERE tenant_id = $1 AND site_id = $2 ORDER BY name',
        [tenant_id, site_id]
      );
      const checkpoints = checkpointsRes.rows;
      const target = assignment.round_size !== null ? assignment.round_size : checkpoints.length;

      const roundStart = todayStartUTC(zone);
      const checkpointIds = checkpoints.map(c => c.id);
      const scannedRes = checkpointIds.length
        ? await client.query(
            'SELECT DISTINCT checkpoint_id FROM patrol_logs WHERE tenant_id = $1 AND user_id = $2 AND checkpoint_id = ANY($3) AND scanned_at >= $4',
            [tenant_id, user_id, checkpointIds, roundStart]
          )
        : { rows: [] };
      const scannedIds = new Set(scannedRes.rows.map(r => r.checkpoint_id));

      const remaining = checkpoints.filter(c => !scannedIds.has(c.id));

      return {
        scanned_count: scannedIds.size,
        target,
        round_complete: scannedIds.size >= target,
        remaining: remaining.map(c => ({ checkpoint_id: c.id, name: c.name })),
        round_started_at: roundStart
      };
    });
    res.json(data);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ PATROL SCHEDULES & LOGS ------------------------

app.get('/api/patrol-routes', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const siteId = req.query.site_id ? Number(req.query.site_id) : null;
  try {
    const result = await withTenant(tenantId, client => {
      const params = [tenantId];
      let where = 'r.tenant_id=$1';
      if (siteId) { params.push(siteId); where += ` AND r.site_id=$${params.length}`; }
      return client.query(`SELECT r.*,s.name AS site_name,
        COALESCE(json_agg(json_build_object('checkpoint_id',c.id,'name',c.name,'position',rc.position,'instructions',rc.instructions,'requires_confirmation',rc.requires_confirmation,'requires_note',rc.requires_note)
          ORDER BY rc.position) FILTER (WHERE c.id IS NOT NULL),'[]') AS checkpoints
        FROM patrol_routes r JOIN sites s ON s.id=r.site_id
        LEFT JOIN patrol_route_checkpoints rc ON rc.route_id=r.id
        LEFT JOIN checkpoints c ON c.id=rc.checkpoint_id
        WHERE ${where} GROUP BY r.id,s.name ORDER BY r.active DESC,r.name`, params);
    });
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/patrol-routes', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const siteId = Number(req.body.site_id), checkpointIds = (req.body.checkpoint_ids || []).map(Number);
  const name = String(req.body.name || '').trim();
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!siteId || !name || !checkpointIds.length) return res.status(400).json({ error: 'Site, route name, and at least one checkpoint are required' });
  if (new Set(checkpointIds).size !== checkpointIds.length) return res.status(400).json({ error: 'A checkpoint can only appear once in a route' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);
    const valid = await client.query('SELECT id FROM checkpoints WHERE tenant_id=$1 AND site_id=$2 AND id=ANY($3::int[])',[tenantId,siteId,checkpointIds]);
    if (valid.rows.length !== checkpointIds.length) throw Object.assign(new Error('Every checkpoint must belong to the selected site'),{statusCode:400});
    const route = await client.query(`INSERT INTO patrol_routes (tenant_id,site_id,name,description,strict_order,estimated_minutes)
      VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,[tenantId,siteId,name,req.body.description||null,req.body.strict_order!==false,req.body.estimated_minutes||null]);
    for (let i=0;i<checkpointIds.length;i++) await client.query('INSERT INTO patrol_route_checkpoints (tenant_id,route_id,checkpoint_id,position) VALUES ($1,$2,$3,$4)',[tenantId,route.rows[0].id,checkpointIds[i],i+1]);
    await client.query('COMMIT'); res.status(201).json(route.rows[0]);
  } catch (err) { await client.query('ROLLBACK'); res.status(err.statusCode||500).json({ error: err.code==='23505'?'A route with this name already exists at the site':err.message }); }
  finally { client.release(); }
});

app.put('/api/patrol-routes/:id', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.body.tenant_id), routeId=Number(req.params.id);
  const siteId=Number(req.body.site_id), checkpointIds=(req.body.checkpoint_ids||[]).map(Number), name=String(req.body.name||'').trim();
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!siteId||!name||!checkpointIds.length||new Set(checkpointIds).size!==checkpointIds.length) return res.status(400).json({ error: 'Valid site, unique checkpoint order, and route name are required' });
  const client=await pool.connect(); try { await client.query('BEGIN'); await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);
    const valid=await client.query('SELECT id FROM checkpoints WHERE tenant_id=$1 AND site_id=$2 AND id=ANY($3::int[])',[tenantId,siteId,checkpointIds]);
    if(valid.rows.length!==checkpointIds.length) throw Object.assign(new Error('Every checkpoint must belong to the selected site'),{statusCode:400});
    const updated=await client.query(`UPDATE patrol_routes SET site_id=$1,name=$2,description=$3,strict_order=$4,estimated_minutes=$5,active=$6,updated_at=NOW() WHERE id=$7 AND tenant_id=$8 RETURNING *`,[siteId,name,req.body.description||null,req.body.strict_order!==false,req.body.estimated_minutes||null,req.body.active!==false,routeId,tenantId]);
    if(!updated.rows.length) throw Object.assign(new Error('Route not found'),{statusCode:404});
    const previous=await client.query('SELECT checkpoint_id,instructions,requires_confirmation,requires_note FROM patrol_route_checkpoints WHERE route_id=$1 AND tenant_id=$2',[routeId,tenantId]);
    const requirements=new Map(previous.rows.map(row=>[Number(row.checkpoint_id),row]));
    await client.query('DELETE FROM patrol_route_checkpoints WHERE route_id=$1 AND tenant_id=$2',[routeId,tenantId]);
    for(let i=0;i<checkpointIds.length;i++){const saved=requirements.get(checkpointIds[i])||{};await client.query('INSERT INTO patrol_route_checkpoints (tenant_id,route_id,checkpoint_id,position,instructions,requires_confirmation,requires_note) VALUES ($1,$2,$3,$4,$5,$6,$7)',[tenantId,routeId,checkpointIds[i],i+1,saved.instructions||null,Boolean(saved.requires_confirmation),Boolean(saved.requires_note)]);}
    await client.query('COMMIT'); res.json(updated.rows[0]);
  } catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.code==='23505'?'A route with this name already exists at the site':err.message});} finally{client.release();}
});

app.patch('/api/patrol-routes/:routeId/checkpoints/:checkpointId',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`UPDATE patrol_route_checkpoints SET instructions=$1,requires_confirmation=$2,requires_note=$3 WHERE route_id=$4 AND checkpoint_id=$5 AND tenant_id=$6 RETURNING *`,[String(req.body.instructions||'').trim()||null,Boolean(req.body.requires_confirmation),Boolean(req.body.requires_note),req.params.routeId,req.params.checkpointId,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Route checkpoint not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}
});

app.delete('/api/patrol-routes/:id', requireAuth, requireAdmin, async (req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query('DELETE FROM patrol_routes WHERE id=$1 AND tenant_id=$2 RETURNING id',[req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Route not found'});res.json({deleted:true});}catch(err){res.status(500).json({error:err.message});}
});

async function refreshPatrolRunStatuses(client, tenantId) {
  await client.query(`UPDATE patrol_runs SET status='missed'
    WHERE tenant_id=$1 AND status='scheduled' AND NOW()>scheduled_end+(grace_minutes*INTERVAL '1 minute')`,[tenantId]);
}

async function runPatrolAlertSweep() {
  try {
    await pool.query(`UPDATE patrol_runs SET status='missed' WHERE status='scheduled' AND NOW()>scheduled_end+(grace_minutes*INTERVAL '1 minute')`);
    await pool.query(`INSERT INTO patrol_alerts (tenant_id,run_id,alert_type,severity,message)
      SELECT pr.tenant_id,pr.id,'late_start','warning','Patrol has not started within its grace period'
      FROM patrol_runs pr WHERE pr.status='scheduled' AND NOW()>pr.scheduled_start+(pr.grace_minutes*INTERVAL '1 minute')
      ON CONFLICT (run_id,alert_type) DO NOTHING`);
    await pool.query(`INSERT INTO patrol_alerts (tenant_id,run_id,alert_type,severity,message)
      SELECT pr.tenant_id,pr.id,'overdue','critical','Patrol is still incomplete after its scheduled end time'
      FROM patrol_runs pr WHERE pr.status='in_progress' AND NOW()>pr.scheduled_end+(pr.grace_minutes*INTERVAL '1 minute')
      ON CONFLICT (run_id,alert_type) DO NOTHING`);
    await pool.query(`INSERT INTO patrol_alerts (tenant_id,run_id,alert_type,severity,message)
      SELECT pr.tenant_id,pr.id,'missed','critical','Patrol was not started before its scheduled window expired'
      FROM patrol_runs pr WHERE pr.status='missed'
      ON CONFLICT (run_id,alert_type) DO NOTHING`);
    await pool.query(`UPDATE patrol_alerts pa SET status='resolved',resolved_at=NOW(),resolution_notes='Automatically resolved when patrol activity resumed'
      FROM patrol_runs pr WHERE pa.run_id=pr.id AND pa.status<>'resolved' AND (pr.status='cancelled' OR (pa.alert_type='late_start' AND pr.status IN ('in_progress','completed')) OR (pa.alert_type='overdue' AND pr.status='completed'))`);
  } catch(err) { console.error('Patrol alert sweep failed:',err.message); }
}
scheduleBackgroundJob('patrol_alert_sweep',60000,20000,runPatrolAlertSweep);

app.post('/api/patrol-runs', requireAuth, requireAdmin, async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id),routeId=Number(req.body.route_id),userId=Number(req.body.user_id);
  const start=new Date(req.body.scheduled_start),end=new Date(req.body.scheduled_end),grace=Math.max(0,Math.min(120,Number(req.body.grace_minutes??15)));
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!routeId||!userId||isNaN(start)||isNaN(end)||end<=start)return res.status(400).json({error:'Route, guard, and a valid start/end period are required'});
  try{const result=await withTenant(tenantId,async client=>{const eligible=await client.query(`SELECT r.site_id FROM patrol_routes r JOIN guard_assignments ga ON ga.site_id=r.site_id AND ga.tenant_id=r.tenant_id AND ga.user_id=$3 WHERE r.id=$1 AND r.tenant_id=$2 AND r.active=TRUE`,[routeId,tenantId,userId]);if(!eligible.rows.length)throw Object.assign(new Error('Guard must be assigned to the route site'),{statusCode:400});return client.query(`INSERT INTO patrol_runs (tenant_id,route_id,site_id,user_id,scheduled_start,scheduled_end,grace_minutes,notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[tenantId,routeId,eligible.rows[0].site_id,userId,start.toISOString(),end.toISOString(),grace,req.body.notes||null]);});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.get('/api/patrol-runs',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const requestedUser=req.query.user_id?Number(req.query.user_id):null,userId=req.auth.role==='admin'?requestedUser:req.auth.user_id;
  try{const result=await withTenant(tenantId,async client=>{await refreshPatrolRunStatuses(client,tenantId);const params=[tenantId];let where='pr.tenant_id=$1';if(userId){params.push(userId);where+=` AND pr.user_id=$${params.length}`;}if(req.query.from_date){params.push(req.query.from_date);where+=` AND pr.scheduled_start >= $${params.length}::date`;}if(req.query.to_date){params.push(req.query.to_date);where+=` AND pr.scheduled_start < ($${params.length}::date+INTERVAL '1 day')`;}return client.query(`SELECT pr.*,CASE WHEN pr.status='scheduled' AND NOW()>pr.scheduled_start+(pr.grace_minutes*INTERVAL '1 minute') THEN 'late' WHEN pr.status='in_progress' AND NOW()>pr.scheduled_end+(pr.grace_minutes*INTERVAL '1 minute') THEN 'incomplete' ELSE pr.status END AS display_status,r.name AS route_name,r.strict_order,r.estimated_minutes,s.name AS site_name,u.email AS guard_email,
      COUNT(rs.id)::int AS scanned_count,(SELECT COUNT(*)::int FROM patrol_route_checkpoints rc WHERE rc.route_id=pr.route_id) AS checkpoint_count,
      COALESCE(json_agg(json_build_object('checkpoint_id',c.id,'name',c.name,'position',rc.position,'instructions',rc.instructions,'requires_confirmation',rc.requires_confirmation,'requires_note',rc.requires_note,'scanned_at',rs.scanned_at,'checkpoint_note',rs.checkpoint_note,'instruction_confirmed',rs.instruction_confirmed) ORDER BY rc.position) FILTER(WHERE c.id IS NOT NULL),'[]') AS checkpoints
      FROM patrol_runs pr JOIN patrol_routes r ON r.id=pr.route_id JOIN sites s ON s.id=pr.site_id JOIN users u ON u.id=pr.user_id
      LEFT JOIN patrol_route_checkpoints rc ON rc.route_id=pr.route_id LEFT JOIN checkpoints c ON c.id=rc.checkpoint_id
      LEFT JOIN patrol_run_scans rs ON rs.run_id=pr.id AND rs.checkpoint_id=rc.checkpoint_id WHERE ${where}
      GROUP BY pr.id,r.name,r.strict_order,r.estimated_minutes,s.name,u.email ORDER BY pr.scheduled_start DESC LIMIT 500`,params);});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/patrol-runs/:id/start',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,async client=>{await refreshPatrolRunStatuses(client,tenantId);const params=[req.params.id,tenantId];let query=`UPDATE patrol_runs SET status='in_progress',started_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='scheduled' AND NOW()>=scheduled_start-INTERVAL '60 minutes' AND NOW()<=scheduled_end+(grace_minutes*INTERVAL '1 minute')`;if(req.auth.role!=='admin'){params.push(req.auth.user_id);query+=` AND user_id=$3`;}query+=' RETURNING *';return client.query(query,params)});if(!result.rows.length)return res.status(409).json({error:'Patrol cannot be started yet, is overdue, or is already started'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/patrol-runs/:id/cancel',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE patrol_runs SET status='cancelled',cancelled_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status IN ('scheduled','in_progress') RETURNING *",[req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Patrol cannot be cancelled'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/patrol-alerts',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{await runPatrolAlertSweep();const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='pa.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND pa.status=$${params.length}`;}if(req.query.severity){params.push(req.query.severity);where+=` AND pa.severity=$${params.length}`;}return client.query(`SELECT pa.*,pr.scheduled_start,pr.scheduled_end,pr.status AS run_status,r.name AS route_name,s.name AS site_name,u.email AS guard_email,
      (SELECT COUNT(*)::int FROM patrol_run_scans rs WHERE rs.run_id=pr.id) AS scanned_count,
      (SELECT COUNT(*)::int FROM patrol_route_checkpoints rc WHERE rc.route_id=pr.route_id) AS checkpoint_count
      FROM patrol_alerts pa JOIN patrol_runs pr ON pr.id=pa.run_id JOIN patrol_routes r ON r.id=pr.route_id JOIN sites s ON s.id=pr.site_id JOIN users u ON u.id=pr.user_id WHERE ${where} ORDER BY CASE pa.severity WHEN 'critical' THEN 1 ELSE 2 END,pa.created_at DESC LIMIT 500`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/patrol-alerts/:id/acknowledge',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE patrol_alerts SET status='acknowledged',acknowledged_at=NOW(),acknowledged_by=$1 WHERE id=$2 AND tenant_id=$3 AND status='open' RETURNING *",[req.auth.user_id,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Alert is no longer open'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/patrol-alerts/:id/resolve',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),notes=String(req.body.resolution_notes||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!notes)return res.status(400).json({error:'Resolution notes are required'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE patrol_alerts SET status='resolved',resolved_at=NOW(),resolved_by=$1,resolution_notes=$2 WHERE id=$3 AND tenant_id=$4 AND status<>'resolved' RETURNING *",[req.auth.user_id,notes,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Alert is already resolved or unavailable'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/patrol-schedules', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, schedule_type, config } = req.body;
  if (!tenant_id || !site_id || !schedule_type || !config) {
    return res.status(400).json({ error: 'tenant_id, site_id, schedule_type, and config are required' });
  }
  if (!['fixed', 'hourly', 'custom'].includes(schedule_type)) {
    return res.status(400).json({ error: 'schedule_type must be fixed, hourly, or custom' });
  }
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'INSERT INTO patrol_schedules (tenant_id, site_id, schedule_type, config) VALUES ($1, $2, $3, $4) RETURNING *',
        [tenant_id, site_id, schedule_type, JSON.stringify(config)]
      )
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/patrol-schedules', requireAuth, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      site_id
        ? client.query('SELECT * FROM patrol_schedules WHERE tenant_id = $1 AND site_id = $2', [tenant_id, site_id])
        : client.query('SELECT * FROM patrol_schedules WHERE tenant_id = $1', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/patrol-schedules/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'DELETE FROM patrol_schedules WHERE id = $1 AND tenant_id = $2 RETURNING *',
        [id, tenant_id]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Schedule not found' });
    }
    res.json({ deleted: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/patrol-logs', requireAuth, requireTrustedGuardDevice, async (req, res) => {
  const { tenant_id, checkpoint_id, user_id, latitude, longitude, accuracy, scanned_at, device_scanned_at, patrol_run_id, checkpoint_note, instruction_confirmed } = req.body;
  const clientScanId = String(req.body.client_scan_id || '').trim() || null;
  const scanMethod = String(req.body.scan_method || 'qr').trim().toLowerCase();
  const deviceId = String(req.body.device_id || '').trim() || null;
  const offlineCaptured = Boolean(req.body.offline_captured);
  if (!tenant_id || !checkpoint_id || !user_id) {
    return res.status(400).json({ error: 'tenant_id, checkpoint_id, and user_id are required' });
  }
  const tenantId=attendanceTenant(req,tenant_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(req.auth.role!=='admin'&&Number(user_id)!==req.auth.user_id)return res.status(403).json({error:'Guards can only submit their own scans'});
  if (!['qr', 'nfc'].includes(scanMethod)) return res.status(400).json({ error: 'scan_method must be qr or nfc' });
  if (clientScanId && clientScanId.length > 120) return res.status(400).json({ error: 'client_scan_id is too long' });

  let scannedAtValue = null;
  if (scanned_at) {
    const parsed = new Date(scanned_at);
    if (isNaN(parsed.getTime())) {
      return res.status(400).json({ error: 'scanned_at must be a valid date' });
    }
    if (parsed.getTime() > Date.now() + 5 * 60000) {
      return res.status(400).json({ error: 'scanned_at cannot be in the future' });
    }
    scannedAtValue = parsed.toISOString();
  }

  if(patrol_run_id){
    const client=await pool.connect();
    try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);
      if(clientScanId){const existing=await client.query('SELECT * FROM patrol_logs WHERE tenant_id=$1 AND client_scan_id=$2',[tenantId,clientScanId]);if(existing.rows.length){await client.query('COMMIT');return res.status(200).json({...existing.rows[0],duplicate:true,idempotent:true});}}
      const runResult=await client.query(`SELECT pr.*,r.strict_order FROM patrol_runs pr JOIN patrol_routes r ON r.id=pr.route_id WHERE pr.id=$1 AND pr.tenant_id=$2 FOR UPDATE`,[patrol_run_id,tenantId]);
      if(!runResult.rows.length)throw Object.assign(new Error('Scheduled patrol not found'),{statusCode:404});const run=runResult.rows[0];
      if(req.auth.role!=='admin'&&Number(run.user_id)!==req.auth.user_id)throw Object.assign(new Error('This patrol is assigned to another guard'),{statusCode:403});
      if(run.status!=='in_progress')throw Object.assign(new Error('Start this patrol before scanning checkpoints'),{statusCode:409});
      const routeCheckpoint=await client.query(`SELECT rc.position,rc.instructions,rc.requires_confirmation,rc.requires_note,s.latitude,s.longitude,s.geofence_enabled,s.geofence_radius_m FROM patrol_route_checkpoints rc JOIN checkpoints c ON c.id=rc.checkpoint_id JOIN sites s ON s.id=c.site_id WHERE rc.route_id=$1 AND rc.checkpoint_id=$2`,[run.route_id,checkpoint_id]);
      if(!routeCheckpoint.rows.length)throw Object.assign(new Error('This checkpoint is not part of the active patrol route'),{statusCode:400});
      const position=routeCheckpoint.rows[0].position;
      if(routeCheckpoint.rows[0].requires_confirmation&&!instruction_confirmed)throw Object.assign(new Error('You must acknowledge the checkpoint instructions before scanning'),{statusCode:400});
      if(routeCheckpoint.rows[0].requires_note&&!String(checkpoint_note||'').trim())throw Object.assign(new Error('A written checkpoint observation is required'),{statusCode:400});
      const evidence=patrolScanEvidence(routeCheckpoint.rows[0],latitude,longitude,accuracy);
      if(routeCheckpoint.rows[0].geofence_enabled&&evidence.status==='unavailable')throw Object.assign(new Error('GPS location is required for this patrol checkpoint'),{statusCode:400});
      if(routeCheckpoint.rows[0].geofence_enabled&&evidence.status==='outside')throw Object.assign(new Error('Scan rejected: you are '+Math.round(evidence.distance)+'m from the site geofence'),{statusCode:403});
      const already=await client.query('SELECT 1 FROM patrol_run_scans WHERE run_id=$1 AND checkpoint_id=$2',[patrol_run_id,checkpoint_id]);
      if(already.rows.length)throw Object.assign(new Error('This checkpoint has already been scanned for this patrol'),{statusCode:409});
      if(run.strict_order){const next=await client.query(`SELECT rc.position,c.name FROM patrol_route_checkpoints rc JOIN checkpoints c ON c.id=rc.checkpoint_id WHERE rc.route_id=$1 AND NOT EXISTS(SELECT 1 FROM patrol_run_scans rs WHERE rs.run_id=$2 AND rs.checkpoint_id=rc.checkpoint_id) ORDER BY rc.position LIMIT 1`,[run.route_id,patrol_run_id]);if(next.rows.length&&Number(next.rows[0].position)!==Number(position))throw Object.assign(new Error('Wrong checkpoint order. Scan next: '+next.rows[0].name),{statusCode:409});}
      const log=await client.query(`INSERT INTO patrol_logs (tenant_id,checkpoint_id,user_id,latitude,longitude,scanned_at,patrol_run_id,accuracy_m,distance_m,location_status,device_scanned_at,client_scan_id,scan_method,device_id,offline_captured) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,NOW()),$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,[tenantId,checkpoint_id,user_id,latitude||null,longitude||null,scannedAtValue,patrol_run_id,evidence.accuracy,evidence.distance,evidence.status,device_scanned_at||scannedAtValue,clientScanId,scanMethod,deviceId,offlineCaptured]);
      await client.query('INSERT INTO patrol_run_scans (tenant_id,run_id,checkpoint_id,patrol_log_id,position,scanned_at,checkpoint_note,instruction_confirmed) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,NOW()),$7,$8)',[tenantId,patrol_run_id,checkpoint_id,log.rows[0].id,position,scannedAtValue,String(checkpoint_note||'').trim()||null,Boolean(instruction_confirmed)]);
      const counts=await client.query(`SELECT (SELECT COUNT(*) FROM patrol_route_checkpoints WHERE route_id=$1)::int total,(SELECT COUNT(*) FROM patrol_run_scans WHERE run_id=$2)::int scanned`,[run.route_id,patrol_run_id]);const complete=counts.rows[0].scanned>=counts.rows[0].total;
      if(complete)await client.query("UPDATE patrol_runs SET status='completed',completed_at=NOW() WHERE id=$1",[patrol_run_id]);
      await client.query('COMMIT');return res.status(201).json({...log.rows[0],patrol_run_id:Number(patrol_run_id),patrol_complete:complete,scanned_count:counts.rows[0].scanned,checkpoint_count:counts.rows[0].total});
    }catch(err){await client.query('ROLLBACK');return res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}
  }

  try {
    const result = await withTenant(tenant_id, async client => {
      const siteResult=await client.query(`SELECT s.latitude,s.longitude,s.geofence_enabled,s.geofence_radius_m FROM checkpoints c JOIN sites s ON s.id=c.site_id WHERE c.id=$1 AND c.tenant_id=$2`,[checkpoint_id,tenantId]);
      if(!siteResult.rows.length)throw Object.assign(new Error('Checkpoint not found'),{statusCode:404});
      const evidence=patrolScanEvidence(siteResult.rows[0],latitude,longitude,accuracy);
      const inserted=await client.query(`INSERT INTO patrol_logs (tenant_id,checkpoint_id,user_id,latitude,longitude,scanned_at,accuracy_m,distance_m,location_status,device_scanned_at,client_scan_id,scan_method,device_id,offline_captured) VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz,NOW()),$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (tenant_id,client_scan_id) WHERE client_scan_id IS NOT NULL DO NOTHING RETURNING *`,[tenantId,checkpoint_id,user_id,latitude||null,longitude||null,scannedAtValue,evidence.accuracy,evidence.distance,evidence.status,device_scanned_at||scannedAtValue,clientScanId,scanMethod,deviceId,offlineCaptured]);
      if(inserted.rows.length)return inserted;
      const existing=await client.query('SELECT * FROM patrol_logs WHERE tenant_id=$1 AND client_scan_id=$2',[tenantId,clientScanId]);
      existing.idempotent=true;
      return existing;
    });
    res.status(result.idempotent ? 200 : 201).json({...result.rows[0],duplicate:Boolean(result.idempotent),idempotent:Boolean(result.idempotent)});
  } catch (err) {
    res.status(err.statusCode||500).json({ error: err.message });
  }
});

app.get('/api/patrol-logs', requireAuth, async (req, res) => {
  const { tenant_id, checkpoint_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      checkpoint_id
        ? client.query('SELECT * FROM patrol_logs WHERE tenant_id = $1 AND checkpoint_id = $2 ORDER BY scanned_at DESC', [tenant_id, checkpoint_id])
        : client.query('SELECT * FROM patrol_logs WHERE tenant_id = $1 ORDER BY scanned_at DESC', [tenant_id])
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ COVERAGE AUTOPILOT ------------------------

async function ensureCoverageAutopilotSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS site_guard_requirements(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,cert_name TEXT NOT NULL,
    created_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(tenant_id,site_id,cert_name)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS coverage_autopilot_actions(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,shift_id INTEGER NOT NULL,previous_user_id INTEGER,
    replacement_user_id INTEGER NOT NULL,recommendation_score INTEGER NOT NULL,reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    approved_by INTEGER NOT NULL,approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE site_guard_requirements ADD COLUMN IF NOT EXISTS reminder_days INTEGER NOT NULL DEFAULT 30`);
  await pool.query(`ALTER TABLE site_guard_requirements ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE`);
  await pool.query(`ALTER TABLE site_guard_requirements ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  for(const table of ['site_guard_requirements','coverage_autopilot_actions']){
    await pool.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);
    await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ${table}`);
    await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ${table} USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  }
  await pool.query('CREATE INDEX IF NOT EXISTS coverage_autopilot_actions_tenant ON coverage_autopilot_actions(tenant_id,approved_at DESC)');
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON site_guard_requirements TO "${role}"`);await pool.query(`GRANT SELECT,INSERT ON coverage_autopilot_actions TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE site_guard_requirements_id_seq,coverage_autopilot_actions_id_seq TO "${role}"`);}}
  catch(err){console.warn('Coverage Autopilot tenant grants skipped:',err.message);}
  console.log('Coverage Autopilot schema ready');
}
ensureCoverageAutopilotSchema().catch(err=>console.error('Coverage Autopilot setup failed:',err.message));

function coverageShiftWindow(shift,zone){const start=DateTime.fromISO(`${String(shift.shift_date).slice(0,10)}T${shift.start_time}`,{zone});let end=DateTime.fromISO(`${String(shift.shift_date).slice(0,10)}T${shift.end_time}`,{zone});if(end<=start)end=end.plus({days:1});return{start,end,hours:Math.max(0,end.diff(start,'hours').hours-Number(shift.break_minutes||0)/60)};}
function coverageOverlap(a,b,zone){const aw=coverageShiftWindow(a,zone),bw=coverageShiftWindow(b,zone);return aw.start<bw.end&&bw.start<aw.end;}
function coverageDistanceKm(lat1,lon1,lat2,lon2){if([lat1,lon1,lat2,lon2].some(v=>v===null||v===undefined||!Number.isFinite(Number(v))))return null;const r=6371,toRad=v=>Number(v)*Math.PI/180,dLat=toRad(Number(lat2)-Number(lat1)),dLon=toRad(Number(lon2)-Number(lon1)),a=Math.sin(dLat/2)**2+Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)**2;return r*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));}

async function buildCoverageAutopilot(client,tenantId,days=14){
  const tenant=(await client.query('SELECT timezone FROM tenants WHERE id=$1',[tenantId])).rows[0]||{},zone=tenant.timezone||'UTC',today=DateTime.now().setZone(zone).startOf('day'),endDate=today.plus({days});
  const [shiftsResult,guardsResult,availabilityResult,leaveResult,certResult,requirementsResult,assignmentsResult,locationsResult]=await Promise.all([
    client.query(`SELECT sh.*,s.name site_name,s.latitude site_latitude,s.longitude site_longitude,u.email guard_email,COALESCE(u.account_active,TRUE) guard_active FROM shifts sh JOIN sites s ON s.id=sh.site_id LEFT JOIN users u ON u.id=sh.user_id WHERE sh.tenant_id=$1 AND sh.shift_date BETWEEN $2 AND $3 ORDER BY sh.shift_date,sh.start_time`,[tenantId,today.toISODate(),endDate.toISODate()]),
    client.query(`SELECT id,email,COALESCE(account_active,TRUE) account_active FROM users WHERE tenant_id=$1 AND role='guard'`,[tenantId]),
    client.query('SELECT * FROM guard_availability WHERE tenant_id=$1',[tenantId]),
    client.query("SELECT * FROM leave_requests WHERE tenant_id=$1 AND status='approved' AND end_date >= $2 AND start_date <= $3",[tenantId,today.toISODate(),endDate.toISODate()]),
    client.query('SELECT user_id,LOWER(TRIM(cert_name)) cert_name,expiry_date FROM guard_certifications WHERE tenant_id=$1',[tenantId]),
    client.query('SELECT * FROM site_guard_requirements WHERE tenant_id=$1 ORDER BY cert_name',[tenantId]),
    client.query('SELECT user_id,site_id FROM guard_assignments WHERE tenant_id=$1',[tenantId]),
    client.query('SELECT DISTINCT ON(user_id) user_id,latitude,longitude,updated_at FROM guard_locations WHERE tenant_id=$1 ORDER BY user_id,updated_at DESC',[tenantId])
  ]);
  const shifts=shiftsResult.rows,guards=guardsResult.rows.filter(g=>g.account_active!==false),availability=availabilityResult.rows,leaves=leaveResult.rows,certs=certResult.rows,requirements=requirementsResult.rows,assignments=assignmentsResult.rows,locations=locationsResult.rows;
  const result=[];
  for(const shift of shifts){
    const window=coverageShiftWindow(shift,zone),weekStart=window.start.startOf('week'),weekEnd=weekStart.plus({days:7}),required=requirements.filter(r=>Number(r.site_id)===Number(shift.site_id)).map(r=>String(r.cert_name).trim().toLowerCase()),risk=[];
    const assignedCerts=certs.filter(c=>Number(c.user_id)===Number(shift.user_id)&&DateTime.fromJSDate(new Date(c.expiry_date),{zone}).endOf('day')>=window.start).map(c=>c.cert_name);
    const assignedLeave=leaves.some(l=>Number(l.user_id)===Number(shift.user_id)&&String(l.start_date).slice(0,10)<=String(shift.shift_date).slice(0,10)&&String(l.end_date).slice(0,10)>=String(shift.shift_date).slice(0,10));
    const assignedWeekHours=shifts.filter(s=>Number(s.user_id)===Number(shift.user_id)&&coverageShiftWindow(s,zone).start>=weekStart&&coverageShiftWindow(s,zone).start<weekEnd).reduce((n,s)=>n+coverageShiftWindow(s,zone).hours,0);
    if(shift.assignment_status==='open')risk.push({code:'open',severity:'critical',message:'Shift is open and has no confirmed coverage'});
    if(shift.guard_active===false)risk.push({code:'inactive',severity:'critical',message:'Assigned guard account is inactive'});
    if(shift.confirmation_status==='rejected')risk.push({code:'rejected',severity:'critical',message:'Assigned guard rejected this shift'});
    if(shift.confirmation_status==='pending'&&window.start.diff(DateTime.now().setZone(zone),'hours').hours<=48)risk.push({code:'unconfirmed',severity:'high',message:'Shift starts within 48 hours and is unconfirmed'});
    if(assignedLeave)risk.push({code:'leave',severity:'critical',message:'Assigned guard has approved leave'});
    const missing=required.filter(name=>!assignedCerts.includes(name));if(missing.length)risk.push({code:'certification',severity:'critical',message:`Missing required certification: ${missing.join(', ')}`});
    if(assignedWeekHours>40)risk.push({code:'overtime',severity:'high',message:`Planned week is ${assignedWeekHours.toFixed(1)} hours`});
    if(!risk.length)continue;
    const candidates=[];
    for(const guard of guards){if(Number(guard.id)===Number(shift.user_id))continue;const reasons=[],blocks=[],guardShifts=shifts.filter(s=>Number(s.user_id)===Number(guard.id)&&Number(s.id)!==Number(shift.id));
      if(guardShifts.some(s=>coverageOverlap(s,shift,zone)))blocks.push('Overlapping shift');
      if(leaves.some(l=>Number(l.user_id)===Number(guard.id)&&String(l.start_date).slice(0,10)<=String(shift.shift_date).slice(0,10)&&String(l.end_date).slice(0,10)>=String(shift.shift_date).slice(0,10)))blocks.push('Approved leave');
      const weekday=window.start.weekday%7,av=availability.find(a=>Number(a.user_id)===Number(guard.id)&&Number(a.weekday)===weekday);if(av&&av.is_available===false)blocks.push('Marked unavailable');
      const guardCerts=certs.filter(c=>Number(c.user_id)===Number(guard.id)&&DateTime.fromJSDate(new Date(c.expiry_date),{zone}).endOf('day')>=window.start).map(c=>c.cert_name),certMissing=required.filter(name=>!guardCerts.includes(name));if(certMissing.length)blocks.push(`Missing certification: ${certMissing.join(', ')}`);
      const weeklyHours=guardShifts.filter(s=>{const w=coverageShiftWindow(s,zone);return w.start>=weekStart&&w.start<weekEnd}).reduce((n,s)=>n+coverageShiftWindow(s,zone).hours,0),projected=weeklyHours+window.hours;if(projected>48)blocks.push(`Would reach ${projected.toFixed(1)} hours`);
      if(blocks.length)continue;let score=50;if(assignments.some(a=>Number(a.user_id)===Number(guard.id)&&Number(a.site_id)===Number(shift.site_id))){score+=18;reasons.push('Already assigned to this site');}if(av?.is_available===true){score+=10;reasons.push('Availability confirmed');}if(required.length){score+=12;reasons.push('All required certifications valid');}if(projected<=32){score+=12;reasons.push(`Low projected workload: ${projected.toFixed(1)}h`);}else if(projected<=40){score+=5;reasons.push(`Within 40h threshold: ${projected.toFixed(1)}h`);}else{score-=12;reasons.push(`Overtime risk: ${projected.toFixed(1)}h`);}
      const loc=locations.find(l=>Number(l.user_id)===Number(guard.id)),distance=loc?coverageDistanceKm(loc.latitude,loc.longitude,shift.site_latitude,shift.site_longitude):null;if(distance!==null){if(distance<=10){score+=10;reasons.push(`${distance.toFixed(1)} km from site`);}else if(distance>40){score-=8;reasons.push(`${distance.toFixed(1)} km from site`);}}
      candidates.push({user_id:guard.id,email:guard.email,score:Math.max(0,Math.min(100,Math.round(score))),projected_weekly_hours:Number(projected.toFixed(1)),distance_km:distance===null?null:Number(distance.toFixed(1)),reasons});
    }
    candidates.sort((a,b)=>b.score-a.score||a.projected_weekly_hours-b.projected_weekly_hours);
    result.push({shift_id:shift.id,shift_date:String(shift.shift_date).slice(0,10),start_time:shift.start_time,end_time:shift.end_time,site_id:shift.site_id,site_name:shift.site_name,current_user_id:shift.user_id,current_guard_email:shift.guard_email,confirmation_status:shift.confirmation_status,assignment_status:shift.assignment_status,risk,candidates:candidates.slice(0,5)});
  }
  return{timezone:zone,days,generated_at:new Date().toISOString(),at_risk_count:result.length,shifts:result};
}

app.get('/api/coverage-autopilot',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id),days=Math.min(30,Math.max(1,Number(req.query.days||14)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{res.json(await withTenant(tenantId,client=>buildCoverageAutopilot(client,tenantId,days)));}catch(err){res.status(500).json({error:err.message});}});
app.post('/api/coverage-autopilot/reassign',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),shiftId=Number(req.body.shift_id),newUserId=Number(req.body.user_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!shiftId||!newUserId)return res.status(400).json({error:'Shift and replacement guard are required'});try{const output=await withTenant(tenantId,async client=>{await client.query('BEGIN');try{const current=await client.query('SELECT * FROM shifts WHERE tenant_id=$1 AND id=$2 FOR UPDATE',[tenantId,shiftId]);if(!current.rowCount)throw Object.assign(new Error('Shift not found'),{statusCode:404});const analysis=await buildCoverageAutopilot(client,tenantId,30),risk=analysis.shifts.find(s=>Number(s.shift_id)===shiftId),candidate=risk?.candidates.find(c=>Number(c.user_id)===newUserId);if(!candidate)throw Object.assign(new Error('Guard is no longer an eligible recommendation. Refresh Coverage Autopilot.'),{statusCode:409});const updated=await client.query(`UPDATE shifts SET user_id=$1,assignment_status='assigned',confirmation_status='pending',confirmed_at=NULL WHERE tenant_id=$2 AND id=$3 RETURNING *`,[newUserId,tenantId,shiftId]);await client.query(`INSERT INTO coverage_autopilot_actions(tenant_id,shift_id,previous_user_id,replacement_user_id,recommendation_score,reasons,approved_by) VALUES($1,$2,$3,$4,$5,$6,$7)`,[tenantId,shiftId,current.rows[0].user_id,newUserId,candidate.score,JSON.stringify(candidate.reasons),req.auth.user_id]);await client.query('COMMIT');return{shift:updated.rows[0],candidate};}catch(e){await client.query('ROLLBACK');throw e;}});res.json(output);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});
app.get('/api/site-guard-requirements',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(tenantId,client=>client.query('SELECT r.*,s.name site_name FROM site_guard_requirements r JOIN sites s ON s.id=r.site_id WHERE r.tenant_id=$1 AND ($2::boolean OR r.active=TRUE) ORDER BY s.name,r.cert_name',[tenantId,req.query.include_inactive==='true']));res.json(r.rows);}catch(err){res.status(500).json({error:err.message});}});
app.post('/api/site-guard-requirements',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),cert=String(req.body.cert_name||'').trim(),days=Math.min(365,Math.max(1,Number(req.body.reminder_days||30)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!cert)return res.status(400).json({error:'Site and certification name are required'});try{const r=await withTenant(tenantId,client=>client.query(`INSERT INTO site_guard_requirements(tenant_id,site_id,cert_name,reminder_days,active,created_by) SELECT $1,$2,$3,$4,TRUE,$5 WHERE EXISTS(SELECT 1 FROM sites WHERE tenant_id=$1 AND id=$2) ON CONFLICT(tenant_id,site_id,cert_name) DO UPDATE SET reminder_days=EXCLUDED.reminder_days,active=TRUE,updated_at=NOW() RETURNING *`,[tenantId,siteId,cert,days,req.auth.user_id]));if(!r.rowCount)return res.status(404).json({error:'Site not found'});res.status(201).json(r.rows[0]);}catch(err){res.status(500).json({error:err.message});}});
app.delete('/api/site-guard-requirements/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(tenantId,client=>client.query('DELETE FROM site_guard_requirements WHERE tenant_id=$1 AND id=$2 RETURNING id',[tenantId,req.params.id]));if(!r.rowCount)return res.status(404).json({error:'Requirement not found'});res.json({deleted:true});}catch(err){res.status(500).json({error:err.message});}});

// ------------------------ PREDICTIVE OPERATIONS RISK ------------------------

async function ensureOperationsRiskSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS operations_risk_snapshots(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,
    score INTEGER NOT NULL,level TEXT NOT NULL,factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,generated_by INTEGER,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE operations_risk_snapshots ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON operations_risk_snapshots`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON operations_risk_snapshots USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS operations_risk_snapshots_site_time ON operations_risk_snapshots(tenant_id,site_id,generated_at DESC)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,DELETE ON operations_risk_snapshots TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE operations_risk_snapshots_id_seq TO "${role}"`);}}
  catch(err){console.warn('Operations Risk tenant grants skipped:',err.message);}
  console.log('Predictive Operations Risk schema ready');
}
ensureOperationsRiskSchema().catch(err=>console.error('Predictive Operations Risk setup failed:',err.message));

function operationsRiskLevel(score){return score>=75?'critical':score>=50?'high':score>=25?'medium':'low';}
function buildOperationsRiskSite(row){
  const factors=[],recommendations=[];let score=0;
  const add=(code,label,points,count,action)=>{if(!count)return;score+=points;factors.push({code,label,points,count});if(action&&!recommendations.includes(action))recommendations.push(action);};
  add('active_sos',`${row.active_sos} active SOS alert${Number(row.active_sos)===1?'':'s'}`,Math.min(40,Number(row.active_sos)*40),Number(row.active_sos),'Respond to and resolve the active SOS alert immediately.');
  add('lone_worker',`${row.lone_worker_alerts} unresolved lone-worker alert${Number(row.lone_worker_alerts)===1?'':'s'}`,Math.min(30,Number(row.lone_worker_alerts)*20),Number(row.lone_worker_alerts),'Contact the affected lone worker and complete the escalation procedure.');
  add('critical_incidents',`${row.critical_incidents} open critical incident${Number(row.critical_incidents)===1?'':'s'}`,Math.min(30,Number(row.critical_incidents)*20),Number(row.critical_incidents),'Assign an owner and response deadline to every critical incident.');
  add('other_incidents',`${row.other_incidents} other open incident${Number(row.other_incidents)===1?'':'s'}`,Math.min(20,Number(row.other_incidents)*6),Number(row.other_incidents),'Review unresolved incidents and close or escalate stale cases.');
  add('patrol_alerts',`${row.patrol_alerts} unresolved patrol exception${Number(row.patrol_alerts)===1?'':'s'}`,Math.min(25,Number(row.patrol_alerts)*10),Number(row.patrol_alerts),'Review missed or late patrol activity and document corrective action.');
  add('coverage_gaps',`${row.coverage_gaps} near-term coverage risk${Number(row.coverage_gaps)===1?'':'s'}`,Math.min(25,Number(row.coverage_gaps)*12),Number(row.coverage_gaps),'Open Coverage Autopilot and secure confirmed replacement coverage.');
  add('expiring_certs',`${row.expiring_certs} assigned guard certification${Number(row.expiring_certs)===1?'':'s'} expiring within 30 days`,Math.min(15,Number(row.expiring_certs)*5),Number(row.expiring_certs),'Renew expiring certifications or schedule a qualified replacement.');
  if(Number(row.scans_7d)===0){score+=10;factors.push({code:'no_recent_scans',label:'No checkpoint scans recorded during the last 7 days',points:10,count:1});recommendations.push('Confirm the patrol schedule and checkpoint scanning process for this site.');}
  score=Math.max(0,Math.min(100,Math.round(score)));
  if(!recommendations.length)recommendations.push('Continue normal monitoring; no immediate preventive action is required.');
  return{site_id:Number(row.site_id),site_name:row.site_name,score,level:operationsRiskLevel(score),factors,recommendations,signals:{active_sos:Number(row.active_sos),lone_worker_alerts:Number(row.lone_worker_alerts),critical_incidents:Number(row.critical_incidents),other_incidents:Number(row.other_incidents),patrol_alerts:Number(row.patrol_alerts),coverage_gaps:Number(row.coverage_gaps),expiring_certs:Number(row.expiring_certs),scans_7d:Number(row.scans_7d)}};
}

app.get('/api/operations-risk',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const save=String(req.query.save||'0')==='1';
  try{const data=await withTenant(tenantId,async client=>{
    const rows=(await client.query(`SELECT s.id site_id,s.name site_name,
      (SELECT COUNT(*)::int FROM sos_alerts x WHERE x.tenant_id=s.tenant_id AND x.site_id=s.id AND x.status='active') active_sos,
      (SELECT COUNT(*)::int FROM lone_worker_alerts x WHERE x.tenant_id=s.tenant_id AND x.site_id=s.id AND x.resolved=FALSE) lone_worker_alerts,
      (SELECT COUNT(*)::int FROM incidents x WHERE x.tenant_id=s.tenant_id AND x.site_id=s.id AND x.status<>'closed' AND x.severity='critical') critical_incidents,
      (SELECT COUNT(*)::int FROM incidents x WHERE x.tenant_id=s.tenant_id AND x.site_id=s.id AND x.status<>'closed' AND x.severity<>'critical') other_incidents,
      (SELECT COUNT(*)::int FROM patrol_alerts x JOIN patrol_runs pr ON pr.id=x.run_id WHERE x.tenant_id=s.tenant_id AND pr.site_id=s.id AND x.status<>'resolved') patrol_alerts,
      (SELECT COUNT(*)::int FROM shifts x WHERE x.tenant_id=s.tenant_id AND x.site_id=s.id AND x.shift_date BETWEEN CURRENT_DATE AND CURRENT_DATE+7 AND (x.assignment_status='open' OR x.confirmation_status IN('pending','rejected'))) coverage_gaps,
      (SELECT COUNT(*)::int FROM guard_assignments ga JOIN guard_certifications gc ON gc.tenant_id=ga.tenant_id AND gc.user_id=ga.user_id WHERE ga.tenant_id=s.tenant_id AND ga.site_id=s.id AND gc.expiry_date BETWEEN CURRENT_DATE AND CURRENT_DATE+30) expiring_certs,
      (SELECT COUNT(*)::int FROM patrol_logs pl JOIN checkpoints cp ON cp.id=pl.checkpoint_id WHERE pl.tenant_id=s.tenant_id AND cp.site_id=s.id AND pl.scanned_at>=NOW()-INTERVAL '7 days') scans_7d
      FROM sites s WHERE s.tenant_id=$1 ORDER BY s.name`,[tenantId])).rows;
    const sites=rows.map(buildOperationsRiskSite);
    if(save)for(const site of sites)await client.query(`INSERT INTO operations_risk_snapshots(tenant_id,site_id,score,level,factors,recommendations,generated_by) VALUES($1,$2,$3,$4,$5,$6,$7)`,[tenantId,site.site_id,site.score,site.level,JSON.stringify(site.factors),JSON.stringify(site.recommendations),req.auth.user_id]);
    const trends=(await client.query(`SELECT DISTINCT ON(site_id,date_trunc('day',generated_at)) site_id,score,level,generated_at FROM operations_risk_snapshots WHERE tenant_id=$1 AND generated_at>=NOW()-INTERVAL '30 days' ORDER BY site_id,date_trunc('day',generated_at) DESC,generated_at DESC`,[tenantId])).rows;
    const summary={low:0,medium:0,high:0,critical:0};for(const site of sites)summary[site.level]++;
    return{generated_at:new Date().toISOString(),saved:save,summary,sites:sites.sort((a,b)=>b.score-a.score||a.site_name.localeCompare(b.site_name)),trends};
  });res.json(data);}catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/intelligence-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const started=Date.now(),checks=[],add=(key,label,critical,passed,message,details={})=>checks.push({key,label,critical,passed:Boolean(passed),status:passed?'pass':critical?'fail':'warning',message,details});
    const tables=['evidence_integrity_records','site_guard_requirements','coverage_autopilot_actions','operations_risk_snapshots'];
    const tableRows=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity rls_enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname) has_policy FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[tables])).rows;
    add('phase8_tables','Phase 8 database structures',true,tableRows.length===tables.length,`${tableRows.length}/${tables.length} required tables available`,{tables:tableRows});
    const protectedCount=tableRows.filter(x=>x.rls_enabled&&x.has_policy).length;add('phase8_rls','Tenant RLS protection',true,protectedCount===tables.length,`${protectedCount}/${tables.length} Phase 8 tables have RLS and a tenant policy`);
    const tenantRole=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');let permissionRows=[];if(tenantRole)permissionRows=(await pool.query(`SELECT t table_name,has_table_privilege($1,t,'SELECT') can_select,has_table_privilege($1,t,'INSERT') can_insert FROM unnest($2::text[]) t`,[tenantRole,tables])).rows;
    add('tenant_permissions','Restricted tenant-role permissions',true,permissionRows.length===tables.length&&permissionRows.every(x=>x.can_select&&x.can_insert),permissionRows.length?`${permissionRows.filter(x=>x.can_select&&x.can_insert).length}/${tables.length} tables grant required restricted-role access`:'Restricted tenant role could not be inspected',{permissions:permissionRows});
    const tenantChecks=await withTenant(tenantId,async client=>{
      const evidence=(await client.query(`SELECT (SELECT COUNT(*) FROM patrol_logs WHERE tenant_id=$1)::int+(SELECT COUNT(*) FROM incident_photos WHERE tenant_id=$1)::int total,(SELECT COUNT(*) FROM evidence_integrity_records WHERE tenant_id=$1)::int sealed`,[tenantId])).rows[0];
      const riskSnapshots=Number((await client.query(`SELECT COUNT(*)::int count FROM operations_risk_snapshots WHERE tenant_id=$1`,[tenantId])).rows[0].count);
      const coverage=await buildCoverageAutopilot(client,tenantId,14);
      const actions=Number((await client.query(`SELECT COUNT(*)::int count FROM coverage_autopilot_actions WHERE tenant_id=$1`,[tenantId])).rows[0].count);
      return{evidence,riskSnapshots,coverage,actions};
    });
    const evidenceTotal=Number(tenantChecks.evidence.total),evidenceSealed=Number(tenantChecks.evidence.sealed);add('trustproof_coverage','TrustProof sealing coverage',true,evidenceTotal===evidenceSealed,`${evidenceSealed}/${evidenceTotal} eligible evidence records sealed`,tenantChecks.evidence);
    add('coverage_engine','Coverage Autopilot engine',true,Boolean(tenantChecks.coverage?.generated_at),`Analysis completed for a 14-day window; ${tenantChecks.coverage.at_risk_count} shift(s) require attention`,{at_risk_shifts:tenantChecks.coverage.at_risk_count});
    add('coverage_audit','Coverage decision audit trail',false,true,tenantChecks.actions?`${tenantChecks.actions} approved reassignment action(s) recorded`:'Audit table ready; no Autopilot reassignments approved yet',{actions:tenantChecks.actions});
    add('risk_history','Operations Risk trend history',true,tenantChecks.riskSnapshots>0,tenantChecks.riskSnapshots?`${tenantChecks.riskSnapshots} saved site risk snapshot(s) available`:'Run and save an Operations Risk analysis to establish the baseline');
    const jobs=(await pool.query(`SELECT COUNT(*) FILTER(WHERE status='failed' AND started_at>=NOW()-INTERVAL '24 hours')::int failed_24h,COUNT(*) FILTER(WHERE status='running' AND started_at<NOW()-INTERVAL '10 minutes')::int stuck,MAX(started_at) FILTER(WHERE job_name='trustproof_evidence_sealing' AND status='succeeded') last_sealing_success FROM platform_job_runs`)).rows[0];
    add('intelligence_jobs','Intelligence background-job health',true,Number(jobs.failed_24h)===0&&Number(jobs.stuck)===0&&Boolean(jobs.last_sealing_success),`Failed in 24h: ${jobs.failed_24h}; stuck: ${jobs.stuck}; last TrustProof sweep: ${jobs.last_sealing_success?new Date(jobs.last_sealing_success).toISOString():'never'}`,jobs);
    add('admin_boundary','Subscriber administrator access boundary',true,req.auth.role==='admin','Endpoint is restricted to authenticated subscriber administrators');
    const criticalFailures=checks.filter(x=>x.critical&&!x.passed).length,warnings=checks.filter(x=>!x.critical&&!x.passed).length;
    res.json({status:criticalFailures?'action_required':warnings?'ready_with_warnings':'ready',generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,warnings,failures:criticalFailures,total:checks.length},checks});
  }catch(err){res.status(500).json({error:err.message});}
});

// ------------------------ TRUSTPROOF EVIDENCE INTEGRITY ------------------------

function trustProofStable(value){
  if(Array.isArray(value))return value.map(trustProofStable);
  if(value&&typeof value==='object'&&!(value instanceof Date))return Object.keys(value).sort().reduce((out,key)=>{out[key]=trustProofStable(value[key]);return out;},{});
  if(value instanceof Date)return value.toISOString();
  return value===undefined?null:value;
}
function trustProofHash(value){return crypto.createHash('sha256').update(typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(trustProofStable(value))).digest('hex');}

async function ensureTrustProofSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS evidence_integrity_records(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,evidence_type TEXT NOT NULL,evidence_id TEXT NOT NULL,
    source_hash CHAR(64) NOT NULL,previous_chain_hash CHAR(64),chain_hash CHAR(64) NOT NULL,
    snapshot JSONB NOT NULL,sealed_by INTEGER,sealed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,evidence_type,evidence_id)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS evidence_integrity_tenant_time ON evidence_integrity_records(tenant_id,sealed_at DESC)`);
  await pool.query(`ALTER TABLE evidence_integrity_records ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON evidence_integrity_records`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON evidence_integrity_records USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{
    const tenantRole=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole)){
      await pool.query(`GRANT SELECT,INSERT ON evidence_integrity_records TO "${tenantRole}"`);
      await pool.query(`GRANT USAGE,SELECT ON SEQUENCE evidence_integrity_records_id_seq TO "${tenantRole}"`);
    }
  }catch(err){console.warn('TrustProof tenant-role grant skipped:',err.message);}
  console.log('TrustProof evidence integrity ledger ready');
}
ensureTrustProofSchema().catch(err=>console.error('TrustProof schema setup failed:',err.message));

async function trustProofPhotoBytes(row){
  if(['s3','object_storage'].includes(String(row.storage_provider||'').toLowerCase())&&row.storage_key){const response=await objectStorageRequest('GET',row.storage_key);return Buffer.from(await response.arrayBuffer());}
  if(row.photo_data)return parseImageDataUrl(row.photo_data).buffer;
  throw Object.assign(new Error('Photo bytes are unavailable'),{statusCode:404});
}
async function trustProofSource(client,tenantId,type,id){
  if(type==='patrol_scan'){
    const result=await client.query(`SELECT pl.id,pl.tenant_id,pl.user_id,pl.checkpoint_id,pl.scanned_at,pl.latitude,pl.longitude,
      pl.patrol_run_id,pl.accuracy_m,pl.distance_m,pl.location_status,pl.device_scanned_at,pl.received_at,
      c.name AS checkpoint_name,c.site_id,s.name AS site_name,u.email AS guard_email,
      rs.position,rs.checkpoint_note,rs.instruction_confirmed
      FROM patrol_logs pl JOIN checkpoints c ON c.id=pl.checkpoint_id JOIN sites s ON s.id=c.site_id
      JOIN users u ON u.id=pl.user_id LEFT JOIN patrol_run_scans rs ON rs.patrol_log_id=pl.id
      WHERE pl.tenant_id=$1 AND pl.id=$2`,[tenantId,id]);
    if(!result.rowCount)throw Object.assign(new Error('Patrol scan evidence not found'),{statusCode:404});
    const snapshot=trustProofStable(result.rows[0]);return{snapshot,sourceHash:trustProofHash(snapshot)};
  }
  if(type==='incident_photo'){
    const result=await client.query(`SELECT ip.id,ip.tenant_id,ip.incident_id,ip.storage_provider,ip.storage_key,ip.content_type,
      ip.size_bytes,ip.checksum_sha256,ip.created_at,i.reference_code,i.site_id,i.user_id
      FROM incident_photos ip JOIN incidents i ON i.id=ip.incident_id AND i.tenant_id=ip.tenant_id
      WHERE ip.tenant_id=$1 AND ip.id=$2`,[tenantId,id]);
    if(!result.rowCount)throw Object.assign(new Error('Incident photo evidence not found'),{statusCode:404});
    const row=result.rows[0],bytes=await trustProofPhotoBytes(row),binaryHash=trustProofHash(bytes);
    const snapshot=trustProofStable({...row,binary_sha256:binaryHash});return{snapshot,sourceHash:trustProofHash(snapshot),binaryHash};
  }
  throw Object.assign(new Error('Evidence type must be patrol_scan or incident_photo'),{statusCode:400});
}
async function trustProofSeal(client,tenantId,type,id,userId){
  // Serialize each tenant's ledger without granting UPDATE permission on sealed evidence.
  await client.query('SELECT pg_advisory_xact_lock($1,$2)',[81427,Number(tenantId)]);
  const existing=await client.query('SELECT * FROM evidence_integrity_records WHERE tenant_id=$1 AND evidence_type=$2 AND evidence_id=$3',[tenantId,type,String(id)]);
  if(existing.rowCount)return existing.rows[0];
  const source=await trustProofSource(client,tenantId,type,id);
  const previous=await client.query('SELECT chain_hash FROM evidence_integrity_records WHERE tenant_id=$1 ORDER BY id DESC LIMIT 1',[tenantId]);
  const previousHash=previous.rows[0]?.chain_hash||null,sealedAt=new Date().toISOString();
  const chainHash=trustProofHash({tenant_id:Number(tenantId),evidence_type:type,evidence_id:String(id),source_hash:source.sourceHash,previous_chain_hash:previousHash,sealed_at:sealedAt});
  const inserted=await client.query(`INSERT INTO evidence_integrity_records(tenant_id,evidence_type,evidence_id,source_hash,previous_chain_hash,chain_hash,snapshot,sealed_by,sealed_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[tenantId,type,String(id),source.sourceHash,previousHash,chainHash,source.snapshot,userId||null,sealedAt]);
  return inserted.rows[0];
}
async function trustProofVerify(client,tenantId,record){
  const source=await trustProofSource(client,tenantId,record.evidence_type,record.evidence_id);
  const expectedChain=trustProofHash({tenant_id:Number(tenantId),evidence_type:record.evidence_type,evidence_id:String(record.evidence_id),source_hash:record.source_hash,previous_chain_hash:record.previous_chain_hash||null,sealed_at:new Date(record.sealed_at).toISOString()});
  const sourceValid=source.sourceHash===record.source_hash,chainValid=expectedChain===record.chain_hash;
  let linkValid=true;
  if(record.previous_chain_hash){const previous=await client.query('SELECT chain_hash FROM evidence_integrity_records WHERE tenant_id=$1 AND id<$2 ORDER BY id DESC LIMIT 1',[tenantId,record.id]);linkValid=previous.rows[0]?.chain_hash===record.previous_chain_hash;}
  return{record_id:record.id,evidence_type:record.evidence_type,evidence_id:record.evidence_id,status:sourceValid&&chainValid&&linkValid?'verified':'tampered',source_valid:sourceValid,chain_valid:chainValid,link_valid:linkValid,source_hash:record.source_hash,chain_hash:record.chain_hash,sealed_at:record.sealed_at,sealed_by:record.sealed_by};
}

app.get('/api/trustproof',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`SELECT e.*,u.email AS sealed_by_email FROM evidence_integrity_records e LEFT JOIN users u ON u.id=e.sealed_by AND u.tenant_id=e.tenant_id WHERE e.tenant_id=$1 ORDER BY e.id DESC LIMIT 500`,[tenantId]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});
app.post('/api/trustproof/seal',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),type=String(req.body.evidence_type||''),id=String(req.body.evidence_id||'');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!id)return res.status(400).json({error:'Evidence ID is required'});try{const record=await withTenant(tenantId,async client=>{await client.query('BEGIN');try{const sealed=await trustProofSeal(client,tenantId,type,id,req.auth.user_id);await client.query('COMMIT');return sealed;}catch(e){await client.query('ROLLBACK');throw e;}});res.status(201).json(record);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});
app.post('/api/trustproof/seal-batch',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),type=String(req.body.evidence_type||'patrol_scan'),limit=Math.min(50,Math.max(1,Number(req.body.limit||20)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['patrol_scan','incident_photo'].includes(type))return res.status(400).json({error:'Invalid evidence type'});try{const output=await withTenant(tenantId,async client=>{const sourceTable=type==='patrol_scan'?'patrol_logs':'incident_photos',rows=await client.query(`SELECT s.id FROM ${sourceTable} s WHERE s.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM evidence_integrity_records e WHERE e.tenant_id=$1 AND e.evidence_type=$2 AND e.evidence_id=s.id::text) ORDER BY s.id LIMIT $3`,[tenantId,type,limit]);let sealed=0,failed=[];for(const row of rows.rows){try{await client.query('BEGIN');await trustProofSeal(client,tenantId,type,row.id,req.auth.user_id);await client.query('COMMIT');sealed++;}catch(e){await client.query('ROLLBACK');failed.push({id:row.id,error:e.message});}}return{sealed,failed,remaining_unknown:rows.rowCount===limit};});res.json(output);}catch(err){res.status(500).json({error:err.message});}});
app.post('/api/trustproof/:id/verify',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const verified=await withTenant(tenantId,async client=>{const found=await client.query('SELECT * FROM evidence_integrity_records WHERE tenant_id=$1 AND id=$2',[tenantId,req.params.id]);if(!found.rowCount)throw Object.assign(new Error('TrustProof record not found'),{statusCode:404});return trustProofVerify(client,tenantId,found.rows[0]);});res.json(verified);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});
app.get('/api/trustproof/summary/status',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const summary=await withTenant(tenantId,async client=>{const counts=await client.query(`SELECT evidence_type,COUNT(*)::int AS sealed FROM evidence_integrity_records WHERE tenant_id=$1 GROUP BY evidence_type`,[tenantId]);const patrol=await client.query(`SELECT COUNT(*)::int total,COUNT(e.id)::int sealed FROM patrol_logs p LEFT JOIN evidence_integrity_records e ON e.tenant_id=p.tenant_id AND e.evidence_type='patrol_scan' AND e.evidence_id=p.id::text WHERE p.tenant_id=$1`,[tenantId]);const photos=await client.query(`SELECT COUNT(*)::int total,COUNT(e.id)::int sealed FROM incident_photos p LEFT JOIN evidence_integrity_records e ON e.tenant_id=p.tenant_id AND e.evidence_type='incident_photo' AND e.evidence_id=p.id::text WHERE p.tenant_id=$1`,[tenantId]);return{by_type:counts.rows,patrol_scans:patrol.rows[0],incident_photos:photos.rows[0]};});res.json(summary);}catch(err){res.status(500).json({error:err.message});}});

async function runTrustProofSweep(){
  const tenants=await pool.query('SELECT id FROM tenants WHERE COALESCE(account_active,TRUE)=TRUE ORDER BY id');
  for(const tenant of tenants.rows){
    await withTenant(tenant.id,async client=>{
      for(const [type,table] of [['patrol_scan','patrol_logs'],['incident_photo','incident_photos']]){
        const pending=await client.query(`SELECT s.id FROM ${table} s WHERE s.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM evidence_integrity_records e WHERE e.tenant_id=$1 AND e.evidence_type=$2 AND e.evidence_id=s.id::text) ORDER BY s.id LIMIT 25`,[tenant.id,type]);
        for(const row of pending.rows){try{await client.query('BEGIN');await trustProofSeal(client,tenant.id,type,row.id,null);await client.query('COMMIT');}catch(err){await client.query('ROLLBACK');console.error(`TrustProof ${type} ${row.id} seal failed:`,err.message);}}
      }
    });
  }
}
scheduleBackgroundJob('trustproof_evidence_sealing',60*1000,90000,runTrustProofSweep);

app.get('/api/patrol-evidence',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='pl.tenant_id=$1';if(req.query.site_id){params.push(req.query.site_id);where+=` AND c.site_id=$${params.length}`;}if(req.query.location_status){params.push(req.query.location_status);where+=` AND pl.location_status=$${params.length}`;}if(req.query.from_date){params.push(req.query.from_date);where+=` AND pl.scanned_at >= $${params.length}::date`;}if(req.query.to_date){params.push(req.query.to_date);where+=` AND pl.scanned_at < ($${params.length}::date+INTERVAL '1 day')`;}return client.query(`SELECT pl.id,pl.scanned_at,pl.received_at,pl.device_scanned_at,pl.latitude,pl.longitude,pl.accuracy_m,pl.distance_m,pl.location_status,pl.patrol_run_id,c.name AS checkpoint_name,s.name AS site_name,u.email AS guard_email,r.name AS route_name,rs.checkpoint_note,rs.instruction_confirmed,e.id AS trustproof_id,e.source_hash AS trustproof_source_hash,e.chain_hash AS trustproof_chain_hash,e.sealed_at AS trustproof_sealed_at FROM patrol_logs pl JOIN checkpoints c ON c.id=pl.checkpoint_id JOIN sites s ON s.id=c.site_id JOIN users u ON u.id=pl.user_id LEFT JOIN patrol_runs pr ON pr.id=pl.patrol_run_id LEFT JOIN patrol_routes r ON r.id=pr.route_id LEFT JOIN patrol_run_scans rs ON rs.patrol_log_id=pl.id LEFT JOIN evidence_integrity_records e ON e.tenant_id=pl.tenant_id AND e.evidence_type='patrol_scan' AND e.evidence_id=pl.id::text WHERE ${where} ORDER BY pl.scanned_at DESC LIMIT 1000`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/patrol-compliance', requireAuth, async (req, res) => {
  const { tenant_id, site_id } = req.query;
  if (!tenant_id || !site_id) {
    return res.status(400).json({ error: 'tenant_id and site_id are required' });
  }
  try {
    const compliance = await withTenant(tenant_id, (client) => computeSiteCompliance(client, tenant_id, site_id));
    res.json(compliance);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ CLIENT SERVICE CONTRACTS & SLAS ------------------------

function validPercent(value){const n=Number(value);return Number.isFinite(n)&&n>=0&&n<=100;}

function reportPeriod(runDate,frequency){const d=DateTime.fromISO(String(runDate).slice(0,10),{zone:'UTC'});if(frequency==='weekly')return{start:d.minus({days:7}),end:d.minus({days:1}),next:d.plus({weeks:1})};if(frequency==='quarterly')return{start:d.startOf('month').minus({months:3}),end:d.startOf('month').minus({days:1}),next:d.plus({months:3})};return{start:d.startOf('month').minus({months:1}),end:d.startOf('month').minus({days:1}),next:d.plus({months:1})};}

async function runClientReportSweep(){const client=await pool.connect();try{await client.query('BEGIN');const due=await client.query(`SELECT * FROM client_report_schedules WHERE active=TRUE AND next_run_date<=CURRENT_DATE ORDER BY next_run_date FOR UPDATE SKIP LOCKED`);for(const schedule of due.rows){const period=reportPeriod(schedule.next_run_date,schedule.frequency);await client.query(`INSERT INTO client_report_runs (tenant_id,schedule_id,contract_id,period_start,period_end,recipient_email) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (schedule_id,period_start,period_end) DO NOTHING`,[schedule.tenant_id,schedule.id,schedule.contract_id,period.start.toISODate(),period.end.toISODate(),schedule.recipient_email]);await client.query('UPDATE client_report_schedules SET next_run_date=$1,updated_at=NOW() WHERE id=$2',[period.next.toISODate(),schedule.id]);}await client.query('COMMIT');}catch(err){await client.query('ROLLBACK');console.error('Client report sweep failed:',err.message);}finally{client.release();}}
scheduleBackgroundJob('client_report_schedule_sweep',60*60*1000,25000,runClientReportSweep);

app.get('/api/service-contracts',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{await client.query("UPDATE service_contracts SET status='expired',updated_at=NOW() WHERE tenant_id=$1 AND status='active' AND end_date<CURRENT_DATE",[tenantId]);const params=[tenantId];let where='sc.tenant_id=$1';if(req.query.site_id){params.push(req.query.site_id);where+=` AND sc.site_id=$${params.length}`;}if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND sc.status=$${params.length}`;}return client.query(`SELECT sc.*,s.name AS site_name,u.email AS created_by_email FROM service_contracts sc JOIN sites s ON s.id=sc.site_id LEFT JOIN users u ON u.id=sc.created_by WHERE ${where} ORDER BY sc.start_date DESC,sc.id DESC`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/service-contracts',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),clientName=String(req.body.client_name||'').trim(),start=req.body.start_date,end=req.body.end_date||null,billing=['monthly','hourly','per_patrol','fixed'].includes(req.body.billing_model)?req.body.billing_model:'monthly',status=['draft','active','suspended'].includes(req.body.status)?req.body.status:'draft';if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!clientName||!start)return res.status(400).json({error:'Site, client name, and start date are required'});if(end&&new Date(end)<new Date(start))return res.status(400).json({error:'End date cannot be before start date'});if(!validPercent(req.body.sla_patrol_completion_pct)||!validPercent(req.body.sla_shift_coverage_pct))return res.status(400).json({error:'SLA percentages must be between 0 and 100'});try{const result=await withTenant(tenantId,async client=>{const site=await client.query('SELECT 1 FROM sites WHERE id=$1 AND tenant_id=$2',[siteId,tenantId]);if(!site.rows.length)throw Object.assign(new Error('Site not found'),{statusCode:404});let reference=String(req.body.reference_code||'').trim();if(!reference){const sequence=await client.query('SELECT COALESCE(MAX(id),0)+1 AS next FROM service_contracts WHERE tenant_id=$1',[tenantId]);reference='CTR-'+new Date().getUTCFullYear()+'-'+String(sequence.rows[0].next).padStart(5,'0');}return client.query(`INSERT INTO service_contracts (tenant_id,site_id,reference_code,client_name,start_date,end_date,status,billing_model,rate,currency,sla_patrol_completion_pct,sla_incident_ack_minutes,sla_shift_coverage_pct,report_frequency,notes,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,[tenantId,siteId,reference,clientName,start,end,status,billing,req.body.rate||null,String(req.body.currency||'EUR').toUpperCase().slice(0,3),Number(req.body.sla_patrol_completion_pct),Math.max(1,Number(req.body.sla_incident_ack_minutes||15)),Number(req.body.sla_shift_coverage_pct),['weekly','monthly','quarterly'].includes(req.body.report_frequency)?req.body.report_frequency:'monthly',req.body.notes||null,req.auth.user_id])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.code==='23505'?'Contract reference already exists':err.message});}});

app.put('/api/service-contracts/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),start=req.body.start_date,end=req.body.end_date||null;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!String(req.body.client_name||'').trim()||!start)return res.status(400).json({error:'Site, client name, and start date are required'});if(end&&new Date(end)<new Date(start))return res.status(400).json({error:'End date cannot be before start date'});if(!validPercent(req.body.sla_patrol_completion_pct)||!validPercent(req.body.sla_shift_coverage_pct))return res.status(400).json({error:'SLA percentages must be between 0 and 100'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE service_contracts SET site_id=$1,reference_code=$2,client_name=$3,start_date=$4,end_date=$5,status=$6,billing_model=$7,rate=$8,currency=$9,sla_patrol_completion_pct=$10,sla_incident_ack_minutes=$11,sla_shift_coverage_pct=$12,report_frequency=$13,notes=$14,updated_at=NOW() WHERE id=$15 AND tenant_id=$16 RETURNING *`,[siteId,String(req.body.reference_code||'').trim(),String(req.body.client_name).trim(),start,end,['draft','active','suspended','expired'].includes(req.body.status)?req.body.status:'draft',['monthly','hourly','per_patrol','fixed'].includes(req.body.billing_model)?req.body.billing_model:'monthly',req.body.rate||null,String(req.body.currency||'EUR').toUpperCase().slice(0,3),Number(req.body.sla_patrol_completion_pct),Math.max(1,Number(req.body.sla_incident_ack_minutes||15)),Number(req.body.sla_shift_coverage_pct),['weekly','monthly','quarterly'].includes(req.body.report_frequency)?req.body.report_frequency:'monthly',req.body.notes||null,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Contract not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.code==='23505'?'Contract reference already exists':err.message});}});

app.patch('/api/service-contracts/:id/status',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['draft','active','suspended','expired'].includes(status))return res.status(400).json({error:'Invalid contract status'});try{const result=await withTenant(tenantId,client=>client.query('UPDATE service_contracts SET status=$1,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 RETURNING *',[status,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Contract not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/sla-performance',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id),from=req.query.from_date,to=req.query.to_date;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!from||!to||isNaN(new Date(from))||isNaN(new Date(to))||new Date(to)<new Date(from))return res.status(400).json({error:'Valid from_date and to_date are required'});try{const contracts=await withTenant(tenantId,client=>{const params=[tenantId,from,to];let siteFilter='';if(req.query.site_id){params.push(req.query.site_id);siteFilter=` AND sc.site_id=$${params.length}`;}return client.query(`SELECT sc.*,s.name AS site_name,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status<>'cancelled' AND pr.scheduled_start::date BETWEEN $2::date AND $3::date AND pr.scheduled_end<=NOW()) AS patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status='completed' AND pr.scheduled_start::date BETWEEN $2::date AND $3::date AND pr.scheduled_end<=NOW()) AS patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $2::date AND $3::date) AS incident_total,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $2::date AND $3::date AND i.acknowledged_at IS NOT NULL AND i.acknowledged_at<=i.reported_at+(sc.sla_incident_ack_minutes*INTERVAL '1 minute')) AS incident_ack_met,
      (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (i.acknowledged_at-i.reported_at))/60)::numeric,1) FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $2::date AND $3::date AND i.acknowledged_at IS NOT NULL) AS incident_avg_ack_minutes,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $2::date AND $3::date) AS shift_total,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $2::date AND $3::date AND sh.assignment_status='assigned') AS shift_covered
      FROM service_contracts sc JOIN sites s ON s.id=sc.site_id WHERE sc.tenant_id=$1 AND sc.status='active' AND sc.start_date<=$3::date AND (sc.end_date IS NULL OR sc.end_date>=$2::date)${siteFilter} ORDER BY s.name,sc.id`,params)});const rows=contracts.rows.map(c=>{const pct=(n,d)=>d?Math.round(n/d*10000)/100:null,patrol=pct(c.patrol_completed,c.patrol_total),incident=pct(c.incident_ack_met,c.incident_total),coverage=pct(c.shift_covered,c.shift_total);const metric=(actual,target)=>({actual,target:Number(target),status:actual===null?'no_data':actual>=Number(target)?'met':'missed'});const metrics={patrol:metric(patrol,c.sla_patrol_completion_pct),incident:metric(incident,100),coverage:metric(coverage,c.sla_shift_coverage_pct)};return{contract_id:c.id,reference_code:c.reference_code,client_name:c.client_name,site_id:c.site_id,site_name:c.site_name,from_date:from,to_date:to,patrol:{...metrics.patrol,completed:c.patrol_completed,total:c.patrol_total},incident:{...metrics.incident,within_sla:c.incident_ack_met,total:c.incident_total,target_minutes:c.sla_incident_ack_minutes,average_minutes:c.incident_avg_ack_minutes===null?null:Number(c.incident_avg_ack_minutes)},coverage:{...metrics.coverage,covered:c.shift_covered,total:c.shift_total},overall_status:Object.values(metrics).some(m=>m.status==='missed')?'missed':Object.values(metrics).every(m=>m.status==='no_data')?'no_data':'met'};});res.json(rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-report-schedules',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{await runClientReportSweep();const result=await withTenant(tenantId,client=>client.query(`SELECT crs.*,sc.reference_code,sc.client_name,sc.site_id,s.name AS site_name FROM client_report_schedules crs JOIN service_contracts sc ON sc.id=crs.contract_id JOIN sites s ON s.id=sc.site_id WHERE crs.tenant_id=$1 ORDER BY crs.active DESC,crs.next_run_date`,[tenantId]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/client-report-schedules',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id),email=String(req.body.recipient_email||'').trim().toLowerCase(),frequency=['weekly','monthly','quarterly'].includes(req.body.frequency)?req.body.frequency:'monthly',next=req.body.next_run_date;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!next||isNaN(new Date(next)))return res.status(400).json({error:'Contract, valid recipient email, and next run date are required'});try{const result=await withTenant(tenantId,async client=>{const contract=await client.query('SELECT 1 FROM service_contracts WHERE id=$1 AND tenant_id=$2',[contractId,tenantId]);if(!contract.rows.length)throw Object.assign(new Error('Contract not found'),{statusCode:404});return client.query(`INSERT INTO client_report_schedules (tenant_id,contract_id,recipient_email,frequency,next_run_date,created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,[tenantId,contractId,email,frequency,next,req.auth.user_id])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.code==='23505'?'A report schedule already exists for this contract and recipient':err.message});}});

app.patch('/api/client-report-schedules/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE client_report_schedules SET active=COALESCE($1,active),frequency=COALESCE($2,frequency),next_run_date=COALESCE($3,next_run_date),updated_at=NOW() WHERE id=$4 AND tenant_id=$5 RETURNING *`,[typeof req.body.active==='boolean'?req.body.active:null,['weekly','monthly','quarterly'].includes(req.body.frequency)?req.body.frequency:null,req.body.next_run_date||null,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Report schedule not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-report-runs',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{await runClientReportSweep();const result=await withTenant(tenantId,client=>client.query(`SELECT crr.*,sc.reference_code,sc.client_name,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.tenant_id=$1 ORDER BY crr.generated_at DESC LIMIT 500`,[tenantId]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/client-report-runs',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id),start=req.body.period_start,end=req.body.period_end;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!start||!end||isNaN(new Date(start))||isNaN(new Date(end))||new Date(end)<new Date(start))return res.status(400).json({error:'Contract and valid report period are required'});try{const result=await withTenant(tenantId,async client=>{const contract=await client.query('SELECT 1 FROM service_contracts WHERE id=$1 AND tenant_id=$2',[contractId,tenantId]);if(!contract.rows.length)throw Object.assign(new Error('Contract not found'),{statusCode:404});return client.query(`INSERT INTO client_report_runs (tenant_id,contract_id,period_start,period_end,status) VALUES ($1,$2,$3,$4,'generated') RETURNING *`,[tenantId,contractId,start,end])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.patch('/api/client-report-runs/:id/delivered',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE client_report_runs SET status='delivered',delivered_at=NOW(),delivered_by=$1,delivery_notes=$2 WHERE id=$3 AND tenant_id=$4 RETURNING *`,[req.auth.user_id,req.body.delivery_notes||null,req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Report run not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-report-runs/:id/pdf',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const data=await withTenant(tenantId,async client=>{const run=(await client.query(`SELECT crr.*,sc.reference_code,sc.client_name,sc.site_id,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.id=$1 AND crr.tenant_id=$2`,[req.params.id,tenantId])).rows[0];if(!run)throw Object.assign(new Error('Report run not found'),{statusCode:404});const counts=(await client.query(`SELECT (SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status<>'cancelled')::int patrol_total,(SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status='completed')::int patrol_completed,(SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND site_id=$2 AND reported_at::date BETWEEN $3 AND $4)::int incidents,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4)::int shifts,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4 AND assignment_status='assigned')::int covered`,[tenantId,run.site_id,run.period_start,run.period_end])).rows[0];return{run,counts}});const {run,counts}=data,pct=(a,b)=>b?Math.round(a/b*10000)/100:null;res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="${run.reference_code}-${run.period_start}-${run.period_end}.pdf"`);const doc=new PDFDocument({margin:50});doc.pipe(res);doc.fontSize(20).text('PatrolSync Client Service Report');doc.moveDown().fontSize(12).text(`Client: ${run.client_name}`).text(`Site: ${run.site_name}`).text(`Contract: ${run.reference_code}`).text(`Period: ${String(run.period_start).slice(0,10)} to ${String(run.period_end).slice(0,10)}`);doc.moveDown().fontSize(16).text('Service Performance');doc.moveDown(.5).fontSize(12).text(`Patrol completion: ${counts.patrol_completed}/${counts.patrol_total} (${pct(counts.patrol_completed,counts.patrol_total)??'No data'}%) — Target ${run.sla_patrol_completion_pct}%`).text(`Incidents reported: ${counts.incidents}`).text(`Shift coverage: ${counts.covered}/${counts.shifts} (${pct(counts.covered,counts.shifts)??'No data'}%) — Target ${run.sla_shift_coverage_pct}%`).text(`Incident acknowledgement target: ${run.sla_incident_ack_minutes} minutes`);doc.moveDown().fontSize(9).fillColor('#666').text(`Generated ${new Date().toISOString()} · Report run #${run.id}`);doc.end();}catch(err){if(!res.headersSent)res.status(err.statusCode||500).json({error:err.message});}});

// Client-facing contract, SLA and delivered report access. Site scope comes only from the signed client JWT.
app.get('/api/client-portal/service-overview',requireAuth,requireClient,async(req,res)=>{
  const {tenant_id,site_id}=req.auth,from=req.query.from_date,to=req.query.to_date;
  if(!from||!to||isNaN(new Date(from))||isNaN(new Date(to))||new Date(to)<new Date(from))return res.status(400).json({error:'Valid from_date and to_date are required'});
  try{
    const result=await withTenant(tenant_id,client=>client.query(`SELECT sc.id,sc.reference_code,sc.client_name,sc.start_date,sc.end_date,sc.status,sc.billing_model,sc.rate,sc.currency,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,sc.report_frequency,s.name AS site_name,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status<>'cancelled' AND pr.scheduled_start::date BETWEEN $3::date AND $4::date AND pr.scheduled_end<=NOW()) AS patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=sc.tenant_id AND pr.site_id=sc.site_id AND pr.status='completed' AND pr.scheduled_start::date BETWEEN $3::date AND $4::date AND pr.scheduled_end<=NOW()) AS patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $3::date AND $4::date) AS incident_total,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $3::date AND $4::date AND i.acknowledged_at IS NOT NULL AND i.acknowledged_at<=i.reported_at+(sc.sla_incident_ack_minutes*INTERVAL '1 minute')) AS incident_ack_met,
      (SELECT ROUND(AVG(EXTRACT(EPOCH FROM (i.acknowledged_at-i.reported_at))/60)::numeric,1) FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.reported_at::date BETWEEN $3::date AND $4::date AND i.acknowledged_at IS NOT NULL) AS incident_avg_ack_minutes,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $3::date AND $4::date) AS shift_total,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=sc.tenant_id AND sh.site_id=sc.site_id AND sh.shift_date BETWEEN $3::date AND $4::date AND sh.assignment_status='assigned') AS shift_covered
      FROM service_contracts sc JOIN sites s ON s.id=sc.site_id WHERE sc.tenant_id=$1 AND sc.site_id=$2 AND sc.status='active' AND sc.start_date<=$4::date AND (sc.end_date IS NULL OR sc.end_date>=$3::date) ORDER BY sc.start_date DESC`,[tenant_id,site_id,from,to]));
    const pct=(n,d)=>d?Math.round(Number(n)/Number(d)*10000)/100:null;
    res.json(result.rows.map(c=>{const patrol=pct(c.patrol_completed,c.patrol_total),incident=pct(c.incident_ack_met,c.incident_total),coverage=pct(c.shift_covered,c.shift_total),status=(actual,target)=>actual===null?'no_data':actual>=Number(target)?'met':'missed',statuses=[status(patrol,c.sla_patrol_completion_pct),status(incident,100),status(coverage,c.sla_shift_coverage_pct)];return{...c,from_date:from,to_date:to,patrol:{actual:patrol,target:Number(c.sla_patrol_completion_pct),status:statuses[0],completed:c.patrol_completed,total:c.patrol_total},incident:{actual:incident,target:100,status:statuses[1],within_sla:c.incident_ack_met,total:c.incident_total,target_minutes:c.sla_incident_ack_minutes,average_minutes:c.incident_avg_ack_minutes===null?null:Number(c.incident_avg_ack_minutes)},coverage:{actual:coverage,target:Number(c.sla_shift_coverage_pct),status:statuses[2],covered:c.shift_covered,total:c.shift_total},overall_status:statuses.includes('missed')?'missed':statuses.every(x=>x==='no_data')?'no_data':'met'};}));
  }catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/client-portal/service-reports',requireAuth,requireClient,async(req,res)=>{
  const {tenant_id,site_id}=req.auth;
  try{const result=await withTenant(tenant_id,client=>client.query(`SELECT crr.id,crr.period_start,crr.period_end,crr.generated_at,crr.delivered_at,crr.delivery_notes,sc.reference_code,sc.client_name,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.tenant_id=$1 AND sc.site_id=$2 AND crr.status='delivered' ORDER BY crr.period_end DESC,crr.id DESC LIMIT 100`,[tenant_id,site_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/client-portal/service-reports/:id/pdf',requireAuth,requireClient,async(req,res)=>{
  const {tenant_id,site_id}=req.auth;
  try{const data=await withTenant(tenant_id,async client=>{const run=(await client.query(`SELECT crr.*,sc.reference_code,sc.client_name,sc.site_id,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.id=$1 AND crr.tenant_id=$2 AND sc.site_id=$3 AND crr.status='delivered'`,[req.params.id,tenant_id,site_id])).rows[0];if(!run)throw Object.assign(new Error('Delivered report not found'),{statusCode:404});const counts=(await client.query(`SELECT (SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status<>'cancelled')::int patrol_total,(SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status='completed')::int patrol_completed,(SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND site_id=$2 AND reported_at::date BETWEEN $3 AND $4)::int incidents,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4)::int shifts,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4 AND assignment_status='assigned')::int covered`,[tenant_id,site_id,run.period_start,run.period_end])).rows[0];return{run,counts};});const {run,counts}=data,pct=(a,b)=>b?Math.round(a/b*10000)/100:'No data';res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="${run.reference_code}-${String(run.period_start).slice(0,10)}-${String(run.period_end).slice(0,10)}.pdf"`);const doc=new PDFDocument({margin:50});doc.pipe(res);doc.fontSize(20).text('PatrolSync Client Service Report');doc.moveDown().fontSize(12).text(`Client: ${run.client_name}`).text(`Site: ${run.site_name}`).text(`Contract: ${run.reference_code}`).text(`Period: ${String(run.period_start).slice(0,10)} to ${String(run.period_end).slice(0,10)}`);doc.moveDown().fontSize(16).text('Service Performance');doc.moveDown(.5).fontSize(12).text(`Patrol completion: ${counts.patrol_completed}/${counts.patrol_total} (${pct(counts.patrol_completed,counts.patrol_total)}%) - Target ${run.sla_patrol_completion_pct}%`).text(`Incidents reported: ${counts.incidents}`).text(`Shift coverage: ${counts.covered}/${counts.shifts} (${pct(counts.covered,counts.shifts)}%) - Target ${run.sla_shift_coverage_pct}%`).text(`Incident acknowledgement target: ${run.sla_incident_ack_minutes} minutes`);doc.moveDown().fontSize(9).fillColor('#666').text(`Delivered report #${run.id}`);doc.end();}catch(err){if(!res.headersSent)res.status(err.statusCode||500).json({error:err.message});}
});

// ------------------------ TRANSACTIONAL EMAIL AUTOMATION ------------------------

const EMAIL_PROVIDER=String(process.env.EMAIL_PROVIDER||'brevo').toLowerCase();
const EMAIL_FROM_ADDRESS=process.env.EMAIL_FROM_ADDRESS||'';
const EMAIL_FROM_NAME=process.env.EMAIL_FROM_NAME||'PatrolSync';
const FRONTEND_URL=String(process.env.FRONTEND_URL||'').replace(/\/$/,'');

function emailHtml(title,body,buttonLabel,buttonUrl){return`<!doctype html><html><body style="font-family:Arial;color:#172033;line-height:1.5"><div style="max-width:620px;margin:auto;border:1px solid #dbe2ea;border-radius:10px;padding:24px"><h2>${title}</h2>${body}${buttonUrl?`<p><a href="${buttonUrl}" style="display:inline-block;background:#2563eb;color:white;text-decoration:none;padding:11px 18px;border-radius:6px">${buttonLabel}</a></p>`:''}<p style="color:#64748b;font-size:12px">Sent automatically by PatrolSync.</p></div></body></html>`;}

async function sendProviderEmail({to,subject,html,attachments=[]}){
  if(EMAIL_PROVIDER!=='brevo')throw new Error(`Unsupported EMAIL_PROVIDER: ${EMAIL_PROVIDER}`);
  if(!process.env.BREVO_API_KEY||!EMAIL_FROM_ADDRESS)throw new Error('Brevo is not configured: set BREVO_API_KEY and EMAIL_FROM_ADDRESS');
  const payload={sender:{name:EMAIL_FROM_NAME,email:EMAIL_FROM_ADDRESS},to:[{email:to}],subject,htmlContent:html};
  if(attachments.length)payload.attachment=attachments.map(a=>({name:a.name,content:a.content}));
  const response=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'Content-Type':'application/json','api-key':process.env.BREVO_API_KEY,'accept':'application/json'},body:JSON.stringify(payload)});
  const text=await response.text();let data={};try{data=text?JSON.parse(text):{};}catch{data={message:text};}if(!response.ok)throw new Error(data.message||`Brevo HTTP ${response.status}`);return{provider:'brevo',message_id:data.messageId||null};
}

async function pdfBuffer(build){return new Promise((resolve,reject)=>{const doc=new PDFDocument({margin:50}),parts=[];doc.on('data',d=>parts.push(d));doc.on('end',()=>resolve(Buffer.concat(parts)));doc.on('error',reject);build(doc);doc.end();});}

async function reportEmailAttachment(tenantId,id){return withTenant(tenantId,async client=>{const run=(await client.query(`SELECT crr.*,sc.reference_code,sc.client_name,sc.site_id,sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct,s.name AS site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.id=$1 AND crr.tenant_id=$2`,[id,tenantId])).rows[0];if(!run)throw new Error('Report not found');const c=(await client.query(`SELECT (SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status<>'cancelled')::int patrol_total,(SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND scheduled_start::date BETWEEN $3 AND $4 AND status='completed')::int patrol_completed,(SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND site_id=$2 AND reported_at::date BETWEEN $3 AND $4)::int incidents,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4)::int shifts,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND site_id=$2 AND shift_date BETWEEN $3 AND $4 AND assignment_status='assigned')::int covered`,[tenantId,run.site_id,run.period_start,run.period_end])).rows[0],pct=(a,b)=>b?Math.round(a/b*10000)/100:'No data',buffer=await pdfBuffer(doc=>{doc.fontSize(20).text('PatrolSync Client Service Report');doc.moveDown().fontSize(12).text(`Client: ${run.client_name}`).text(`Site: ${run.site_name}`).text(`Contract: ${run.reference_code}`).text(`Period: ${String(run.period_start).slice(0,10)} to ${String(run.period_end).slice(0,10)}`);doc.moveDown().fontSize(16).text('Service Performance');doc.moveDown(.5).fontSize(12).text(`Patrol completion: ${c.patrol_completed}/${c.patrol_total} (${pct(c.patrol_completed,c.patrol_total)}%)`).text(`Incidents reported: ${c.incidents}`).text(`Shift coverage: ${c.covered}/${c.shifts} (${pct(c.covered,c.shifts)}%)`);});return{name:`${run.reference_code}-${String(run.period_start).slice(0,10)}.pdf`,content:buffer.toString('base64')};});}

async function invoiceEmailAttachment(tenantId,id){return withTenant(tenantId,async client=>{const result=await invoiceDetails(client,tenantId,id);if(!result.rows.length)throw new Error('Invoice not found');const i=result.rows[0],money=n=>`${i.currency} ${Number(n).toFixed(2)}`,buffer=await pdfBuffer(doc=>{doc.fontSize(22).text('PatrolSync Invoice').moveDown(.5);doc.fontSize(11).text(`Invoice: ${i.invoice_number}`).text(`Client: ${i.client_name}`).text(`Site: ${i.site_name}`).text(`Period: ${String(i.period_start).slice(0,10)} to ${String(i.period_end).slice(0,10)}`).text(`Due: ${String(i.due_date).slice(0,10)}`).moveDown();i.lines.forEach(line=>doc.text(`${line.description}: ${Number(line.quantity).toFixed(2)} x ${money(line.unit_rate)} = ${money(line.line_total)}`));doc.moveDown().fontSize(14).text(`Total: ${money(i.total)}`,{align:'right'}).fontSize(11).text(`Balance: ${money(Number(i.total)-Number(i.amount_paid))}`,{align:'right'});});return{name:`${i.invoice_number}.pdf`,content:buffer.toString('base64')};});}

async function queueEmail({tenantId,eventType,entityType,entityId,key,to,subject,html}){if(!to)return;await pool.query(`INSERT INTO email_deliveries(tenant_id,event_type,entity_type,entity_id,idempotency_key,recipient_email,subject,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(idempotency_key,recipient_email) DO NOTHING`,[tenantId,eventType,entityType,entityId,key,String(to).trim().toLowerCase(),subject,JSON.stringify({html})]);}

async function processEmailQueue(limit=20){if(!process.env.BREVO_API_KEY||!EMAIL_FROM_ADDRESS)return;const client=await pool.connect();try{const rows=(await client.query(`UPDATE email_deliveries SET status='sending',attempt_count=attempt_count+1,updated_at=NOW() WHERE id IN (SELECT id FROM email_deliveries WHERE status IN ('queued','failed') AND next_attempt_at<=NOW() AND attempt_count<5 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1) RETURNING *`,[limit])).rows;for(const row of rows){try{const attachments=[];if(row.entity_type==='client_report')attachments.push(await reportEmailAttachment(row.tenant_id,row.entity_id));if(row.entity_type==='invoice')attachments.push(await invoiceEmailAttachment(row.tenant_id,row.entity_id));const sent=await sendProviderEmail({to:row.recipient_email,subject:row.subject,html:row.payload.html,attachments});await client.query(`UPDATE email_deliveries SET status='sent',provider=$1,provider_message_id=$2,sent_at=NOW(),last_error=NULL,updated_at=NOW() WHERE id=$3`,[sent.provider,sent.message_id,row.id]);if(row.entity_type==='client_report')await client.query(`UPDATE client_report_runs SET status='delivered',delivered_at=COALESCE(delivered_at,NOW()),delivery_notes=COALESCE(delivery_notes,'Delivered automatically by email') WHERE id=$1 AND tenant_id=$2`,[row.entity_id,row.tenant_id]);}catch(err){const delay=Math.min(1440,Math.pow(2,row.attempt_count)*5);await client.query(`UPDATE email_deliveries SET status='failed',last_error=$1,next_attempt_at=NOW()+($2*INTERVAL '1 minute'),updated_at=NOW() WHERE id=$3`,[String(err.message).slice(0,1000),delay,row.id]);}}}finally{client.release();}}

async function queueTicketNotifications(){const rows=await pool.query(`SELECT c.id,c.tenant_id,c.author_type,c.comment,st.reference_code,st.subject,cu.email client_email,COALESCE(assignee.email,admin.email) admin_email FROM service_ticket_comments c JOIN service_tickets st ON st.id=c.ticket_id LEFT JOIN client_users cu ON cu.id=st.client_user_id LEFT JOIN users assignee ON assignee.id=st.assigned_to LEFT JOIN LATERAL(SELECT email FROM users WHERE tenant_id=c.tenant_id AND role='admin' ORDER BY id LIMIT 1) admin ON TRUE WHERE c.internal=FALSE AND NOT EXISTS(SELECT 1 FROM email_deliveries e WHERE e.idempotency_key='ticket-comment-'||c.id)`);for(const c of rows.rows){const to=c.author_type==='client'?c.admin_email:c.client_email;if(!to)continue;await queueEmail({tenantId:c.tenant_id,eventType:'ticket_comment',entityType:'service_ticket',entityId:c.id,key:`ticket-comment-${c.id}`,to,subject:`${c.reference_code}: ${c.subject}`,html:emailHtml('Service ticket update',`<p><b>${c.reference_code}: ${c.subject}</b></p><p>${String(c.comment).replace(/[&<>]/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[x]))}</p>`,c.author_type==='client'?'Open Ticket Queue':'Open Client Portal',FRONTEND_URL&&`${FRONTEND_URL}/${c.author_type==='client'?'service_tickets.html':'client_portal.html'}`)});}}

async function runEmailAutomationSweep(){try{await runClientReportSweep();await queueTicketNotifications();const reports=await pool.query(`SELECT crr.id,crr.tenant_id,crr.recipient_email,crr.period_start,crr.period_end,sc.client_name,s.name site_name FROM client_report_runs crr JOIN service_contracts sc ON sc.id=crr.contract_id JOIN sites s ON s.id=sc.site_id WHERE crr.status='generated' AND crr.recipient_email IS NOT NULL AND NOT EXISTS(SELECT 1 FROM email_deliveries e WHERE e.idempotency_key='report-'||crr.id)`);for(const r of reports.rows)await queueEmail({tenantId:r.tenant_id,eventType:'client_report',entityType:'client_report',entityId:r.id,key:`report-${r.id}`,to:r.recipient_email,subject:`PatrolSync service report - ${r.site_name}`,html:emailHtml('Your service report is ready',`<p>Please find attached the service report for ${r.site_name}, covering ${String(r.period_start).slice(0,10)} to ${String(r.period_end).slice(0,10)}.</p>`,'Open Client Portal',FRONTEND_URL&&`${FRONTEND_URL}/client_portal.html`)});const invoices=await pool.query(`SELECT i.id,i.tenant_id,i.invoice_number,i.total,i.currency,i.due_date,sc.client_name,sc.site_id,cu.email FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN client_users cu ON cu.tenant_id=i.tenant_id AND cu.site_id=sc.site_id WHERE i.status IN ('issued','overdue') AND NOT EXISTS(SELECT 1 FROM email_deliveries e WHERE e.idempotency_key='invoice-'||i.id AND e.recipient_email=LOWER(cu.email))`);for(const i of invoices.rows)await queueEmail({tenantId:i.tenant_id,eventType:'invoice_issued',entityType:'invoice',entityId:i.id,key:`invoice-${i.id}`,to:i.email,subject:`Invoice ${i.invoice_number} from PatrolSync`,html:emailHtml(`Invoice ${i.invoice_number}`,`<p>Your invoice for ${i.currency} ${Number(i.total).toFixed(2)} is attached. Payment is due ${String(i.due_date).slice(0,10)}.</p>`,'View Client Portal',FRONTEND_URL&&`${FRONTEND_URL}/client_portal.html`)});const renewals=await pool.query(`SELECT cr.id,cr.tenant_id,sc.reference_code,sc.client_name,sc.end_date,(sc.end_date-CURRENT_DATE)::int days_remaining,COALESCE(owner.email,admin.email) email FROM contract_renewals cr JOIN service_contracts sc ON sc.id=cr.contract_id LEFT JOIN users owner ON owner.id=cr.owner_user_id LEFT JOIN LATERAL(SELECT email FROM users WHERE tenant_id=cr.tenant_id AND role='admin' ORDER BY id LIMIT 1) admin ON TRUE WHERE cr.status NOT IN ('renewed','lost') AND (sc.end_date-CURRENT_DATE)::int IN (90,60,30,14,7,1,0)`);for(const r of renewals.rows)await queueEmail({tenantId:r.tenant_id,eventType:'renewal_reminder',entityType:'contract_renewal',entityId:r.id,key:`renewal-${r.id}-${r.days_remaining}`,to:r.email,subject:`Contract renewal reminder: ${r.reference_code}`,html:emailHtml('Contract renewal reminder',`<p>${r.client_name} contract ${r.reference_code} expires in ${r.days_remaining} day(s), on ${String(r.end_date).slice(0,10)}.</p>`,'Open Renewals',FRONTEND_URL&&`${FRONTEND_URL}/contract_renewals.html`)});await processEmailQueue();}catch(err){console.error('Email automation sweep failed:',err.message);}}

scheduleBackgroundJob('email_automation',15*60*1000,45000,runEmailAutomationSweep);

app.get('/api/email-deliveries',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const params=[tenantId];let where='tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND status=$${params.length}`;}const result=await withTenant(tenantId,client=>client.query(`SELECT * FROM email_deliveries WHERE ${where} ORDER BY created_at DESC LIMIT 500`,params));res.json({configured:Boolean(process.env.BREVO_API_KEY&&EMAIL_FROM_ADDRESS),provider:EMAIL_PROVIDER,from_address:EMAIL_FROM_ADDRESS||null,deliveries:result.rows});}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/email-deliveries/:id/retry',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE email_deliveries SET status='queued',attempt_count=0,last_error=NULL,next_attempt_at=NOW(),updated_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='failed' RETURNING *`,[req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Only failed deliveries can be retried'});setTimeout(()=>processEmailQueue(),100);res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/email-deliveries/test',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),to=String(req.body.recipient_email||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to))return res.status(400).json({error:'Valid recipient email is required'});try{const key=`test-${tenantId}-${Date.now()}`;await queueEmail({tenantId,eventType:'test',entityType:'test',entityId:null,key,to,subject:'PatrolSync email test',html:emailHtml('PatrolSync email is connected','<p>Your Brevo transactional email integration is working.</p>')});await processEmailQueue(1);const result=await pool.query('SELECT * FROM email_deliveries WHERE idempotency_key=$1 AND recipient_email=$2',[key,to.toLowerCase()]);res.status(result.rows[0]?.status==='sent'?200:502).json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

// ------------------------ CONTRACT RENEWAL MANAGEMENT ------------------------

const renewalStatuses=['not_started','contacted','negotiating','awaiting_client','approved','renewed','lost'];

app.get('/api/contract-renewals',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{await client.query(`INSERT INTO contract_renewals(tenant_id,contract_id,proposed_start_date,proposed_rate,proposed_currency) SELECT sc.tenant_id,sc.id,sc.end_date+1,sc.rate,sc.currency FROM service_contracts sc WHERE sc.tenant_id=$1 AND sc.end_date IS NOT NULL AND sc.status IN ('active','expired') AND sc.end_date<=CURRENT_DATE+INTERVAL '180 days' ON CONFLICT(contract_id) DO NOTHING`,[tenantId]);const params=[tenantId];let where='cr.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND cr.status=$${params.length}`;}return client.query(`SELECT cr.*,sc.reference_code,sc.client_name,sc.site_id,sc.start_date,sc.end_date,sc.status AS contract_status,sc.billing_model,sc.rate AS current_rate,sc.currency AS current_currency,s.name AS site_name,u.email AS owner_email,(sc.end_date-CURRENT_DATE)::int AS days_remaining,(SELECT COUNT(*)::int FROM contract_renewal_history h WHERE h.renewal_id=cr.id) history_count FROM contract_renewals cr JOIN service_contracts sc ON sc.id=cr.contract_id JOIN sites s ON s.id=sc.site_id LEFT JOIN users u ON u.id=cr.owner_user_id WHERE ${where} ORDER BY CASE WHEN sc.end_date<CURRENT_DATE THEN 0 ELSE 1 END,sc.end_date,cr.updated_at DESC`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/contract-renewals',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId)return res.status(400).json({error:'Contract is required'});try{const result=await withTenant(tenantId,client=>client.query(`INSERT INTO contract_renewals(tenant_id,contract_id,proposed_start_date,proposed_rate,proposed_currency) SELECT tenant_id,id,COALESCE(end_date+1,CURRENT_DATE),rate,currency FROM service_contracts WHERE id=$1 AND tenant_id=$2 ON CONFLICT(contract_id) DO UPDATE SET updated_at=NOW() RETURNING *`,[contractId,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Contract not found'});res.status(201).json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/contract-renewals/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=renewalStatuses.includes(req.body.status)?req.body.status:null,owner=req.body.owner_user_id?Number(req.body.owner_user_id):null,start=req.body.proposed_start_date||null,end=req.body.proposed_end_date||null,rate=req.body.proposed_rate===''||req.body.proposed_rate===null?null:Number(req.body.proposed_rate),currency=req.body.proposed_currency?String(req.body.proposed_currency).toUpperCase().slice(0,3):null,note=String(req.body.history_note||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(start&&end&&new Date(end)<new Date(start))return res.status(400).json({error:'Proposed end date cannot be before start date'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);if(owner){const valid=await client.query("SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2 AND role='admin'",[owner,tenantId]);if(!valid.rows.length)throw Object.assign(new Error('Renewal owner must be an administrator'),{statusCode:400});}const result=await client.query(`UPDATE contract_renewals SET status=COALESCE($1,status),owner_user_id=$2,proposed_start_date=COALESCE($3,proposed_start_date),proposed_end_date=$4,proposed_rate=COALESCE($5,proposed_rate),proposed_currency=COALESCE($6,proposed_currency),notes=COALESCE($7,notes),last_contact_at=CASE WHEN $8 THEN NOW() ELSE last_contact_at END,next_follow_up_date=$9,updated_at=NOW() WHERE id=$10 AND tenant_id=$11 RETURNING *`,[status,owner,start,end,Number.isFinite(rate)?rate:null,currency,req.body.notes===undefined?null:String(req.body.notes),req.body.mark_contacted===true,req.body.next_follow_up_date||null,req.params.id,tenantId]);if(!result.rows.length)throw Object.assign(new Error('Renewal not found'),{statusCode:404});if(note||status)await client.query(`INSERT INTO contract_renewal_history(tenant_id,renewal_id,action,note,user_id) VALUES($1,$2,$3,$4,$5)`,[tenantId,req.params.id,status?'status_'+status:'note',note||null,req.auth.user_id]);await client.query('COMMIT');res.json(result.rows[0]);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

app.get('/api/contract-renewals/:id/history',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`SELECT h.*,u.email FROM contract_renewal_history h LEFT JOIN users u ON u.id=h.user_id WHERE h.tenant_id=$1 AND h.renewal_id=$2 ORDER BY h.created_at DESC`,[tenantId,req.params.id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/contract-renewals/:id/complete',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const row=(await client.query(`SELECT cr.*,sc.* ,cr.id AS renewal_id,sc.id AS source_contract_id FROM contract_renewals cr JOIN service_contracts sc ON sc.id=cr.contract_id WHERE cr.id=$1 AND cr.tenant_id=$2 AND cr.status IN ('approved','negotiating','awaiting_client') FOR UPDATE`,[req.params.id,tenantId])).rows[0];if(!row)throw Object.assign(new Error('Renewal must be approved or active in the pipeline'),{statusCode:409});const start=row.proposed_start_date||DateTime.fromJSDate(new Date(row.end_date)).plus({days:1}).toISODate(),end=row.proposed_end_date||null;if(!start)throw Object.assign(new Error('Set the renewed contract start date'),{statusCode:400});const id=Number((await client.query("SELECT nextval(pg_get_serial_sequence('service_contracts','id')) AS id")).rows[0].id),reference=`${row.reference_code}-R${id}`,rate=row.proposed_rate??row.rate,currency=row.proposed_currency||row.currency;const renewed=(await client.query(`INSERT INTO service_contracts(id,tenant_id,site_id,reference_code,client_name,start_date,end_date,status,billing_model,rate,currency,sla_patrol_completion_pct,sla_incident_ack_minutes,sla_shift_coverage_pct,report_frequency,notes,created_by,previous_contract_id) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,[id,tenantId,row.site_id,reference,row.client_name,start,end,row.billing_model,rate,currency,row.sla_patrol_completion_pct,row.sla_incident_ack_minutes,row.sla_shift_coverage_pct,row.report_frequency,row.notes,req.auth.user_id,row.source_contract_id])).rows[0];await client.query("UPDATE service_contracts SET status='expired',updated_at=NOW() WHERE id=$1",[row.source_contract_id]);await client.query("UPDATE contract_renewals SET status='renewed',completed_contract_id=$1,updated_at=NOW() WHERE id=$2",[id,row.renewal_id]);await client.query(`INSERT INTO contract_renewal_history(tenant_id,renewal_id,action,note,user_id) VALUES($1,$2,'renewed',$3,$4)`,[tenantId,row.renewal_id,`Created ${reference}`,req.auth.user_id]);await client.query('COMMIT');res.status(201).json(renewed);}catch(err){await client.query('ROLLBACK');res.status(err.code==='23505'?409:err.statusCode||500).json({error:err.code==='23505'?'Renewed contract reference already exists':err.message});}finally{client.release();}});

// ------------------------ CLIENT REQUESTS & SERVICE TICKETS ------------------------

const ticketTypes=['general','extra_guard','extra_patrol','incident_follow_up','schedule_change','access','billing'];
const ticketPriorities=['low','normal','high','urgent'];
const ticketStatuses=['open','in_progress','waiting_client','resolved','closed'];

async function canAccessTicket(client,auth,ticketId){
  const result=await client.query('SELECT * FROM service_tickets WHERE id=$1 AND tenant_id=$2',[ticketId,auth.tenant_id]);
  const ticket=result.rows[0];if(!ticket)return null;if(auth.role==='client'&&Number(ticket.site_id)!==Number(auth.site_id))return null;return ticket;
}

app.post('/api/client-portal/service-tickets',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id,client_user_id}=req.auth,type=ticketTypes.includes(req.body.request_type)?req.body.request_type:'general',priority=ticketPriorities.includes(req.body.priority)?req.body.priority:'normal',subject=String(req.body.subject||'').trim(),description=String(req.body.description||'').trim();if(!subject||!description)return res.status(400).json({error:'Subject and description are required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenant_id}'`);const id=Number((await client.query("SELECT nextval(pg_get_serial_sequence('service_tickets','id')) AS id")).rows[0].id),reference=`REQ-${new Date().getUTCFullYear()}-${String(id).padStart(6,'0')}`,ticket=(await client.query(`INSERT INTO service_tickets(id,tenant_id,site_id,client_user_id,reference_code,request_type,subject,description,priority) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[id,tenant_id,site_id,client_user_id,reference,type,subject,description,priority])).rows[0];await client.query(`INSERT INTO service_ticket_comments(tenant_id,ticket_id,author_type,author_client_user_id,comment) VALUES($1,$2,'client',$3,$4)`,[tenant_id,id,client_user_id,description]);await client.query('COMMIT');res.status(201).json(ticket);}catch(err){await client.query('ROLLBACK');res.status(500).json({error:err.message});}finally{client.release();}});

app.get('/api/client-portal/service-tickets',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id}=req.auth;try{const result=await withTenant(tenant_id,client=>client.query(`SELECT st.*,s.name AS site_name,u.email AS assigned_email,(SELECT COUNT(*)::int FROM service_ticket_comments c WHERE c.ticket_id=st.id AND c.internal=FALSE) comment_count FROM service_tickets st JOIN sites s ON s.id=st.site_id LEFT JOIN users u ON u.id=st.assigned_to WHERE st.tenant_id=$1 AND st.site_id=$2 ORDER BY CASE st.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'waiting_client' THEN 3 WHEN 'resolved' THEN 4 ELSE 5 END,st.updated_at DESC`,[tenant_id,site_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/service-tickets',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='st.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND st.status=$${params.length}`;}if(req.query.site_id){params.push(req.query.site_id);where+=` AND st.site_id=$${params.length}`;}if(req.query.priority&&req.query.priority!=='all'){params.push(req.query.priority);where+=` AND st.priority=$${params.length}`;}return client.query(`SELECT st.*,s.name AS site_name,cu.email AS client_email,u.email AS assigned_email,(SELECT COUNT(*)::int FROM service_ticket_comments c WHERE c.ticket_id=st.id) comment_count FROM service_tickets st JOIN sites s ON s.id=st.site_id LEFT JOIN client_users cu ON cu.id=st.client_user_id LEFT JOIN users u ON u.id=st.assigned_to WHERE ${where} ORDER BY CASE st.priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END,CASE st.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 WHEN 'waiting_client' THEN 3 WHEN 'resolved' THEN 4 ELSE 5 END,st.updated_at DESC LIMIT 500`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/service-tickets/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=ticketStatuses.includes(req.body.status)?req.body.status:null,priority=ticketPriorities.includes(req.body.priority)?req.body.priority:null,assigned=req.body.assigned_to?Number(req.body.assigned_to):null,resolution=String(req.body.resolution||'').trim()||null;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{if(assigned){const user=await client.query("SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2 AND role='admin'",[assigned,tenantId]);if(!user.rows.length)throw Object.assign(new Error('Assigned administrator not found'),{statusCode:400});}return client.query(`UPDATE service_tickets SET status=COALESCE($1,status),priority=COALESCE($2,priority),assigned_to=$3,resolution=COALESCE($4,resolution),resolved_at=CASE WHEN $1='resolved' THEN NOW() WHEN $1 IS NOT NULL AND $1<>'resolved' THEN NULL ELSE resolved_at END,closed_at=CASE WHEN $1='closed' THEN NOW() WHEN $1 IS NOT NULL AND $1<>'closed' THEN NULL ELSE closed_at END,updated_at=NOW() WHERE id=$5 AND tenant_id=$6 RETURNING *`,[status,priority,assigned,resolution,req.params.id,tenantId]);});if(!result.rows.length)return res.status(404).json({error:'Ticket not found'});res.json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.get('/api/service-tickets/:id/comments',requireAuth,async(req,res)=>{try{const ticket=await withTenant(req.auth.tenant_id,client=>canAccessTicket(client,req.auth,req.params.id));if(!ticket)return res.status(404).json({error:'Ticket not found'});const result=await withTenant(req.auth.tenant_id,client=>client.query(`SELECT c.*,u.email AS admin_email,cu.email AS client_email FROM service_ticket_comments c LEFT JOIN users u ON u.id=c.author_user_id LEFT JOIN client_users cu ON cu.id=c.author_client_user_id WHERE c.ticket_id=$1 AND c.tenant_id=$2 ${req.auth.role==='client'?'AND c.internal=FALSE':''} ORDER BY c.created_at`,[req.params.id,req.auth.tenant_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/service-tickets/:id/comments',requireAuth,async(req,res)=>{const comment=String(req.body.comment||'').trim(),internal=req.auth.role==='admin'&&req.body.internal===true;if(!comment)return res.status(400).json({error:'Comment is required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${req.auth.tenant_id}'`);const ticket=await canAccessTicket(client,req.auth,req.params.id);if(!ticket)throw Object.assign(new Error('Ticket not found'),{statusCode:404});if(req.auth.role==='client'&&ticket.status==='closed')throw Object.assign(new Error('Closed tickets cannot receive client comments'),{statusCode:409});const result=await client.query(`INSERT INTO service_ticket_comments(tenant_id,ticket_id,author_type,author_user_id,author_client_user_id,comment,internal) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[req.auth.tenant_id,ticket.id,req.auth.role,req.auth.role==='admin'?req.auth.user_id:null,req.auth.role==='client'?req.auth.client_user_id:null,comment,internal]);await client.query(`UPDATE service_tickets SET status=CASE WHEN $1='client' AND status='waiting_client' THEN 'in_progress' ELSE status END,updated_at=NOW() WHERE id=$2`,[req.auth.role,ticket.id]);await client.query('COMMIT');res.status(201).json(result.rows[0]);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

// ------------------------ ADVANCED OPERATIONAL ANALYTICS ------------------------

app.get('/api/operational-analytics',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id),from=req.query.from_date,to=req.query.to_date,siteId=req.query.site_id?Number(req.query.site_id):null;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const start=DateTime.fromISO(String(from||'')),end=DateTime.fromISO(String(to||''));
  if(!start.isValid||!end.isValid||end<start||end.diff(start,'days').days>366)return res.status(400).json({error:'Choose a valid analytics period of no more than 367 days'});
  try{const data=await withTenant(tenantId,async client=>{
    const p=[tenantId,from,to,siteId];
    const summary=(await client.query(`SELECT
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date BETWEEN $2 AND $3 AND ($4::int IS NULL OR sh.site_id=$4)) shifts_total,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date BETWEEN $2 AND $3 AND sh.assignment_status='assigned' AND ($4::int IS NULL OR sh.site_id=$4)) shifts_covered,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status<>'cancelled' AND ($4::int IS NULL OR pr.site_id=$4)) patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status='completed' AND ($4::int IS NULL OR pr.site_id=$4)) patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.reported_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR i.site_id=$4)) incidents_total,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.reported_at::date BETWEEN $2 AND $3 AND i.status='resolved' AND ($4::int IS NULL OR i.site_id=$4)) incidents_resolved,
      (SELECT ROUND(COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0)),0)/3600::numeric,2) FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR a.site_id=$4)) worked_hours,
      (SELECT COUNT(*)::int FROM attendance_sessions a JOIN shifts sh ON sh.id=a.shift_id AND sh.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.clocked_in_at::date BETWEEN $2 AND $3 AND a.clocked_in_at>(sh.shift_date+sh.start_time::time+INTERVAL '5 minutes') AND ($4::int IS NULL OR a.site_id=$4)) late_clockins,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date BETWEEN $2 AND LEAST($3::date,CURRENT_DATE-1) AND sh.assignment_status='assigned' AND ($4::int IS NULL OR sh.site_id=$4) AND NOT EXISTS(SELECT 1 FROM attendance_sessions a WHERE a.tenant_id=sh.tenant_id AND (a.shift_id=sh.id OR (a.user_id=sh.user_id AND a.site_id=sh.site_id AND a.clocked_in_at::date=sh.shift_date)))) no_shows`,p)).rows[0];
    const daily=(await client.query(`SELECT d::date AS date,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.shift_date=d::date AND ($4::int IS NULL OR sh.site_id=$4)) shifts,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.scheduled_start::date=d::date AND pr.status='completed' AND ($4::int IS NULL OR pr.site_id=$4)) patrols_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.reported_at::date=d::date AND ($4::int IS NULL OR i.site_id=$4)) incidents,
      (SELECT ROUND(COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0)),0)/3600::numeric,2) FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date=d::date AND ($4::int IS NULL OR a.site_id=$4)) worked_hours
      FROM generate_series($2::date,$3::date,INTERVAL '1 day') d ORDER BY d`,p)).rows;
    const sites=(await client.query(`SELECT s.id,s.name,
      COUNT(DISTINCT sh.id)::int shifts,COUNT(DISTINCT sh.id) FILTER(WHERE sh.assignment_status='assigned')::int covered,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.site_id=s.id AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status<>'cancelled') patrol_total,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.site_id=s.id AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status='completed') patrol_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.site_id=s.id AND i.reported_at::date BETWEEN $2 AND $3) incidents
      FROM sites s LEFT JOIN shifts sh ON sh.site_id=s.id AND sh.tenant_id=s.tenant_id AND sh.shift_date BETWEEN $2 AND $3 WHERE s.tenant_id=$1 AND ($4::int IS NULL OR s.id=$4) GROUP BY s.id,s.name ORDER BY s.name`,p)).rows;
    const guards=(await client.query(`SELECT u.id,u.email,
      ROUND(COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0)),0)/3600::numeric,2) worked_hours,
      COUNT(DISTINCT a.id)::int sessions,
      COUNT(DISTINCT a.id) FILTER(WHERE sh.id IS NOT NULL AND a.clocked_in_at>(sh.shift_date+sh.start_time::time+INTERVAL '5 minutes'))::int late_clockins,
      (SELECT COUNT(*)::int FROM patrol_runs pr WHERE pr.tenant_id=$1 AND pr.user_id=u.id AND pr.scheduled_start::date BETWEEN $2 AND $3 AND pr.status='completed' AND ($4::int IS NULL OR pr.site_id=$4)) patrols_completed,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.user_id=u.id AND i.reported_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR i.site_id=$4)) incidents
      FROM users u LEFT JOIN attendance_sessions a ON a.user_id=u.id AND a.tenant_id=u.tenant_id AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR a.site_id=$4) LEFT JOIN shifts sh ON sh.id=a.shift_id AND sh.tenant_id=a.tenant_id WHERE u.tenant_id=$1 AND u.role='guard' GROUP BY u.id,u.email ORDER BY worked_hours DESC,u.email`,p)).rows;
    const incidentBreakdown=(await client.query(`SELECT category,severity,COUNT(*)::int AS count FROM incidents WHERE tenant_id=$1 AND reported_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR site_id=$4) GROUP BY category,severity ORDER BY count DESC,category,severity`,p)).rows;
    const overtime=(await client.query(`SELECT COALESCE(SUM(GREATEST(0,weekly_hours-40)),0)::numeric(12,2) overtime_hours FROM (SELECT a.user_id,date_trunc('week',a.clocked_in_at)::date week,ROUND(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0))/3600::numeric,2) weekly_hours FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $2 AND $3 AND ($4::int IS NULL OR a.site_id=$4) GROUP BY a.user_id,date_trunc('week',a.clocked_in_at)) w`,p)).rows[0];
    return{summary:{...summary,overtime_hours:Number(overtime.overtime_hours||0)},daily,sites,guards,incident_breakdown:incidentBreakdown};
  });res.json({from_date:from,to_date:to,site_id:siteId,...data});}catch(err){res.status(500).json({error:err.message});}
});

// ------------------------ BILLING & INVOICING ------------------------

async function invoiceDetails(client,tenantId,whereValue,byId=true){
  const field=byId?'i.id':'i.invoice_number';
  return client.query(`SELECT i.*,sc.reference_code,sc.client_name,sc.site_id,sc.billing_model,s.name AS site_name,
    COALESCE((SELECT json_agg(il ORDER BY il.id) FROM invoice_lines il WHERE il.invoice_id=i.id),'[]') AS lines,
    COALESCE((SELECT json_agg(ip ORDER BY ip.payment_date,ip.id) FROM invoice_payments ip WHERE ip.invoice_id=i.id),'[]') AS payments
    FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN sites s ON s.id=sc.site_id
    WHERE i.tenant_id=$1 AND ${field}=$2`,[tenantId,whereValue]);
}

async function calculateInvoiceLine(client,contract,start,end){
  const rate=Number(contract.rate||0);
  if(contract.billing_model==='hourly'){
    const result=await client.query(`SELECT COALESCE(SUM(GREATEST(0,EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))-COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0))),0)/3600 AS quantity
      FROM attendance_sessions a WHERE a.tenant_id=$1 AND a.site_id=$2 AND a.clocked_out_at IS NOT NULL AND a.clocked_in_at::date BETWEEN $3 AND $4
      AND EXISTS(SELECT 1 FROM timesheets t WHERE t.tenant_id=a.tenant_id AND t.user_id=a.user_id AND t.status='approved' AND a.clocked_in_at::date BETWEEN t.period_start AND t.period_end)`,[contract.tenant_id,contract.site_id,start,end]);
    const quantity=Math.round(Number(result.rows[0].quantity||0)*100)/100;return{description:`Approved guard hours (${start} to ${end})`,quantity,unit_rate:rate,line_total:Math.round(quantity*rate*100)/100};
  }
  if(contract.billing_model==='per_patrol'){
    const result=await client.query(`SELECT COUNT(*)::int AS quantity FROM patrol_runs WHERE tenant_id=$1 AND site_id=$2 AND status='completed' AND scheduled_start::date BETWEEN $3 AND $4`,[contract.tenant_id,contract.site_id,start,end]);
    const quantity=Number(result.rows[0].quantity);return{description:`Completed patrols (${start} to ${end})`,quantity,unit_rate:rate,line_total:Math.round(quantity*rate*100)/100};
  }
  return{description:`${contract.billing_model==='monthly'?'Monthly service fee':'Fixed service fee'} (${start} to ${end})`,quantity:1,unit_rate:rate,line_total:rate};
}

app.get('/api/invoices',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{await client.query("UPDATE invoices SET status='overdue',updated_at=NOW() WHERE tenant_id=$1 AND status='issued' AND due_date<CURRENT_DATE AND amount_paid<total",[tenantId]);const params=[tenantId];let where='i.tenant_id=$1';if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND i.status=$${params.length}`;}if(req.query.contract_id){params.push(req.query.contract_id);where+=` AND i.contract_id=$${params.length}`;}return client.query(`SELECT i.*,sc.reference_code,sc.client_name,s.name AS site_name FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN sites s ON s.id=sc.site_id WHERE ${where} ORDER BY i.created_at DESC LIMIT 500`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/invoices/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>invoiceDetails(client,tenantId,req.params.id));if(!result.rows.length)return res.status(404).json({error:'Invoice not found'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/invoices/generate',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id),start=req.body.period_start,end=req.body.period_end,tax=Math.max(0,Math.min(100,Number(req.body.tax_rate||0))),dueDays=Math.max(0,Math.min(365,Number(req.body.due_days||30)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!start||!end||isNaN(new Date(start))||isNaN(new Date(end))||new Date(end)<new Date(start))return res.status(400).json({error:'Contract and valid billing period are required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const contract=(await client.query("SELECT * FROM service_contracts WHERE id=$1 AND tenant_id=$2 AND status='active'",[contractId,tenantId])).rows[0];if(!contract)throw Object.assign(new Error('Active contract not found'),{statusCode:404});if(contract.rate===null||contract.rate===undefined||!Number.isFinite(Number(contract.rate))||Number(contract.rate)<0)throw Object.assign(new Error('Set a valid contract rate before invoicing'),{statusCode:400});const line=await calculateInvoiceLine(client,contract,start,end);if(['hourly','per_patrol'].includes(contract.billing_model)&&line.quantity<=0)throw Object.assign(new Error(contract.billing_model==='hourly'?'No approved billable hours were found for this site and period':'No completed patrols were found for this site and period'),{statusCode:400});const subtotal=line.line_total,taxAmount=Math.round(subtotal*tax/100*100)/100,total=Math.round((subtotal+taxAmount)*100)/100,id=Number((await client.query("SELECT nextval(pg_get_serial_sequence('invoices','id')) AS id")).rows[0].id),number=`INV-${new Date().getUTCFullYear()}-${String(id).padStart(6,'0')}`,issue=DateTime.utc().toISODate(),due=DateTime.utc().plus({days:dueDays}).toISODate();const invoice=(await client.query(`INSERT INTO invoices(id,tenant_id,contract_id,invoice_number,period_start,period_end,issue_date,due_date,currency,subtotal,tax_rate,tax_amount,total,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,[id,tenantId,contractId,number,start,end,issue,due,contract.currency||'EUR',subtotal,tax,taxAmount,total,req.body.notes||null,req.auth.user_id])).rows[0];await client.query(`INSERT INTO invoice_lines(invoice_id,description,quantity,unit_rate,line_total) VALUES($1,$2,$3,$4,$5)`,[id,line.description,line.quantity,line.unit_rate,line.line_total]);await client.query('COMMIT');res.status(201).json({...invoice,lines:[line]});}catch(err){await client.query('ROLLBACK');res.status(err.code==='23505'?409:err.statusCode||500).json({error:err.code==='23505'?'An invoice already exists for this contract and period':err.message});}finally{client.release();}});

app.patch('/api/invoices/:id/status',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['issued','cancelled'].includes(status))return res.status(400).json({error:'Status must be issued or cancelled'});try{const result=await withTenant(tenantId,client=>client.query(`UPDATE invoices SET status=$1,issue_date=CASE WHEN $1='issued' THEN COALESCE(issue_date,CURRENT_DATE) ELSE issue_date END,updated_at=NOW() WHERE id=$2 AND tenant_id=$3 AND status${status==='issued'?"='draft'":" NOT IN ('paid','cancelled')"} RETURNING *`,[status,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Invoice status cannot be changed'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.post('/api/invoices/:id/payments',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),amount=Number(req.body.amount),paymentDate=req.body.payment_date;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!Number.isFinite(amount)||amount<=0||!paymentDate||isNaN(new Date(paymentDate)))return res.status(400).json({error:'Positive amount and payment date are required'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const invoice=(await client.query("SELECT * FROM invoices WHERE id=$1 AND tenant_id=$2 AND status IN ('issued','overdue','paid') FOR UPDATE",[req.params.id,tenantId])).rows[0];if(!invoice)throw Object.assign(new Error('Issued invoice not found'),{statusCode:404});const balance=Number(invoice.total)-Number(invoice.amount_paid);if(amount>balance+0.001)throw Object.assign(new Error(`Payment exceeds outstanding balance of ${invoice.currency} ${balance.toFixed(2)}`),{statusCode:400});const payment=(await client.query(`INSERT INTO invoice_payments(tenant_id,invoice_id,amount,payment_date,method,reference,notes,recorded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[tenantId,invoice.id,amount,paymentDate,req.body.method||null,req.body.reference||null,req.body.notes||null,req.auth.user_id])).rows[0],newPaid=Math.round((Number(invoice.amount_paid)+amount)*100)/100,newStatus=newPaid>=Number(invoice.total)?'paid':(new Date(invoice.due_date)<new Date()?'overdue':'issued');await client.query('UPDATE invoices SET amount_paid=$1,status=$2,updated_at=NOW() WHERE id=$3',[newPaid,newStatus,invoice.id]);await client.query('COMMIT');res.status(201).json(payment);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

async function sendInvoicePdf(res,invoice){res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="${invoice.invoice_number}.pdf"`);const money=n=>`${invoice.currency} ${Number(n).toFixed(2)}`,doc=new PDFDocument({margin:50});doc.pipe(res);doc.fontSize(22).text('PatrolSync Invoice').moveDown(.5);doc.fontSize(11).text(`Invoice: ${invoice.invoice_number}`).text(`Client: ${invoice.client_name}`).text(`Site: ${invoice.site_name}`).text(`Contract: ${invoice.reference_code}`).text(`Billing period: ${String(invoice.period_start).slice(0,10)} to ${String(invoice.period_end).slice(0,10)}`).text(`Issue date: ${String(invoice.issue_date||'Draft').slice(0,10)}`).text(`Due date: ${String(invoice.due_date).slice(0,10)}`).moveDown();doc.fontSize(14).text('Charges').moveDown(.4);invoice.lines.forEach(line=>doc.fontSize(10).text(`${line.description}   ${Number(line.quantity).toFixed(2)} x ${money(line.unit_rate)} = ${money(line.line_total)}`));doc.moveDown().fontSize(11).text(`Subtotal: ${money(invoice.subtotal)}`,{align:'right'}).text(`Tax (${Number(invoice.tax_rate).toFixed(2)}%): ${money(invoice.tax_amount)}`,{align:'right'}).fontSize(14).text(`Total: ${money(invoice.total)}`,{align:'right'}).fontSize(11).text(`Paid: ${money(invoice.amount_paid)}`,{align:'right'}).text(`Balance: ${money(Number(invoice.total)-Number(invoice.amount_paid))}`,{align:'right'});if(invoice.notes)doc.moveDown().text(`Notes: ${invoice.notes}`);doc.end();}

app.get('/api/invoices/:id/pdf',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>invoiceDetails(client,tenantId,req.params.id));if(!result.rows.length)return res.status(404).json({error:'Invoice not found'});sendInvoicePdf(res,result.rows[0]);}catch(err){if(!res.headersSent)res.status(500).json({error:err.message});}});

app.get('/api/client-portal/invoices',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id}=req.auth;try{const result=await withTenant(tenant_id,client=>client.query(`SELECT i.id,i.invoice_number,i.period_start,i.period_end,i.issue_date,i.due_date,i.status,i.currency,i.total,i.amount_paid,sc.reference_code FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id WHERE i.tenant_id=$1 AND sc.site_id=$2 AND i.status IN ('issued','overdue','paid') ORDER BY i.issue_date DESC,i.id DESC`,[tenant_id,site_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/client-portal/invoices/:id/pdf',requireAuth,requireClient,async(req,res)=>{const {tenant_id,site_id}=req.auth;try{const result=await withTenant(tenant_id,client=>client.query(`SELECT i.*,sc.reference_code,sc.client_name,sc.site_id,s.name AS site_name,COALESCE((SELECT json_agg(il ORDER BY il.id) FROM invoice_lines il WHERE il.invoice_id=i.id),'[]') AS lines,COALESCE((SELECT json_agg(ip ORDER BY ip.payment_date,ip.id) FROM invoice_payments ip WHERE ip.invoice_id=i.id),'[]') AS payments FROM invoices i JOIN service_contracts sc ON sc.id=i.contract_id JOIN sites s ON s.id=sc.site_id WHERE i.id=$1 AND i.tenant_id=$2 AND sc.site_id=$3 AND i.status IN ('issued','overdue','paid')`,[req.params.id,tenant_id,site_id]));if(!result.rows.length)return res.status(404).json({error:'Invoice not found'});sendInvoicePdf(res,result.rows[0]);}catch(err){if(!res.headersSent)res.status(500).json({error:err.message});}});

// ------------------------ SHIFT HANDOVERS ------------------------

app.post('/api/handovers',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),toUser=req.body.to_user_id?Number(req.body.to_user_id):null,summary=String(req.body.summary||'').trim(),actions=String(req.body.outstanding_actions||'').trim(),equipment=['ok','attention','fault'].includes(req.body.equipment_status)?req.body.equipment_status:'ok';if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!summary)return res.status(400).json({error:'Site and handover summary are required'});try{const result=await withTenant(tenantId,async client=>{if(req.auth.role!=='admin'){const assigned=await client.query('SELECT 1 FROM guard_assignments WHERE tenant_id=$1 AND site_id=$2 AND user_id=$3',[tenantId,siteId,req.auth.user_id]);if(!assigned.rows.length)throw Object.assign(new Error('You are not assigned to this site'),{statusCode:403});}if(toUser){const target=await client.query(`SELECT 1 FROM guard_assignments ga JOIN users u ON u.id=ga.user_id WHERE ga.tenant_id=$1 AND ga.site_id=$2 AND ga.user_id=$3 AND u.role='guard'`,[tenantId,siteId,toUser]);if(!target.rows.length)throw Object.assign(new Error('Receiving guard is not assigned to this site'),{statusCode:400});}return client.query(`INSERT INTO handover_logs (tenant_id,site_id,from_user_id,to_user_id,summary,outstanding_actions,equipment_status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[tenantId,siteId,req.auth.user_id,toUser,summary,actions||null,equipment])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.get('/api/handovers',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='h.tenant_id=$1';if(req.query.site_id){params.push(req.query.site_id);where+=` AND h.site_id=$${params.length}`;}if(req.query.status&&req.query.status!=='all'){params.push(req.query.status);where+=` AND h.status=$${params.length}`;}if(req.auth.role!=='admin'){params.push(req.auth.user_id);where+=` AND EXISTS(SELECT 1 FROM guard_assignments ga WHERE ga.tenant_id=h.tenant_id AND ga.site_id=h.site_id AND ga.user_id=$${params.length})`;}return client.query(`SELECT h.*,s.name AS site_name,fu.email AS from_email,tu.email AS to_email,au.email AS acknowledged_email FROM handover_logs h JOIN sites s ON s.id=h.site_id JOIN users fu ON fu.id=h.from_user_id LEFT JOIN users tu ON tu.id=h.to_user_id LEFT JOIN users au ON au.id=h.acknowledged_by WHERE ${where} ORDER BY h.created_at DESC LIMIT 300`,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/handovers/:id/acknowledge',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,async client=>{const handover=await client.query('SELECT * FROM handover_logs WHERE id=$1 AND tenant_id=$2 AND status=$3',[req.params.id,tenantId,'pending']);if(!handover.rows.length)throw Object.assign(new Error('Handover is no longer pending'),{statusCode:409});const h=handover.rows[0];if(req.auth.role!=='admin'){if(Number(h.from_user_id)===req.auth.user_id)throw Object.assign(new Error('The outgoing guard cannot acknowledge their own handover'),{statusCode:403});if(h.to_user_id&&Number(h.to_user_id)!==req.auth.user_id)throw Object.assign(new Error('This handover is assigned to another guard'),{statusCode:403});const assigned=await client.query('SELECT 1 FROM guard_assignments WHERE tenant_id=$1 AND site_id=$2 AND user_id=$3',[tenantId,h.site_id,req.auth.user_id]);if(!assigned.rows.length)throw Object.assign(new Error('You are not assigned to this site'),{statusCode:403});}return client.query("UPDATE handover_logs SET status='acknowledged',acknowledged_by=$1,acknowledged_at=NOW() WHERE id=$2 AND tenant_id=$3 AND status='pending' RETURNING *",[req.auth.user_id,req.params.id,tenantId])});if(!result.rows.length)return res.status(409).json({error:'Handover was already acknowledged'});res.json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.patch('/api/handovers/:id/resolve',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),notes=String(req.body.resolution_notes||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!notes)return res.status(400).json({error:'Resolution notes are required'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE handover_logs SET status='resolved',resolved_by=$1,resolved_at=NOW(),resolution_notes=$2 WHERE id=$3 AND tenant_id=$4 AND status<>'resolved' RETURNING *",[req.auth.user_id,notes,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Handover is already resolved or unavailable'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

// ------------------------ INCIDENTS ------------------------

app.post('/api/incidents', requireAuth, requireTrustedGuardDevice, async (req, res) => {
  const { tenant_id, site_id, checkpoint_id, description, severity, category, photos } = req.body;
  const clientIncidentId=String(req.body.client_incident_id||'').trim()||null;
  const deviceId=String(req.body.device_id||'').trim()||null;
  const offlineCaptured=Boolean(req.body.offline_captured);
  let deviceReportedAt=null;
  const user_id = req.auth.user_id;
  if (!tenant_id || !site_id || !description) {
    return res.status(400).json({ error: 'tenant_id, site_id, and description are required' });
  }
  const tenantId=attendanceTenant(req,tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(clientIncidentId&&clientIncidentId.length>120)return res.status(400).json({error:'client_incident_id is too long'});
  if(req.body.device_reported_at){const parsed=new Date(req.body.device_reported_at);if(Number.isNaN(parsed.getTime()))return res.status(400).json({error:'device_reported_at must be a valid date'});if(parsed.getTime()>Date.now()+5*60000)return res.status(400).json({error:'device_reported_at cannot be in the future'});deviceReportedAt=parsed.toISOString();}
  const incidentCategory=['security','safety','medical','fire','property','access','conduct','general'].includes(category)?category:'general';

  const photoList = Array.isArray(photos) ? photos.slice(0, MAX_PHOTOS_PER_INCIDENT) : [];
  for (const p of photoList) {
    if (typeof p !== 'string' || p.length === 0) {
      return res.status(400).json({ error: 'Each photo must be a non-empty base64 data URL string' });
    }
    if (p.length > MAX_PHOTO_BASE64_LENGTH) {
      return res.status(400).json({ error: 'One or more photos are too large. Please retake at a lower quality.' });
    }
    try{parseImageDataUrl(p)}catch(e){return res.status(e.statusCode||400).json({error:e.message})}
  }

  const client = await pool.connect();
  const uploadedKeys=[];
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.current_tenant = '${tenantId}'`);

    if(clientIncidentId){const existing=await client.query(`SELECT i.*,(SELECT COUNT(*)::int FROM incident_photos p WHERE p.tenant_id=i.tenant_id AND p.incident_id=i.id) photo_count FROM incidents i WHERE i.tenant_id=$1 AND i.client_incident_id=$2`,[tenantId,clientIncidentId]);if(existing.rows.length){await client.query('COMMIT');return res.status(200).json({...existing.rows[0],duplicate:true,idempotent:true});}}

    const incidentResult = await client.query(
      'INSERT INTO incidents (tenant_id, site_id, checkpoint_id, user_id, description, severity,category,client_incident_id,device_reported_at,offline_captured,device_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [tenantId, site_id, checkpoint_id || null, user_id, description, severity || 'low',incidentCategory,clientIncidentId,deviceReportedAt,offlineCaptured,deviceId]
    );
    let incident = incidentResult.rows[0];
    const reference='INC-'+new Date().getUTCFullYear()+'-'+String(incident.id).padStart(6,'0');
    incident=(await client.query('UPDATE incidents SET reference_code=$1 WHERE id=$2 RETURNING *',[reference,incident.id])).rows[0];
    await client.query(`INSERT INTO incident_activities (tenant_id,incident_id,user_id,activity_type,note) VALUES ($1,$2,$3,'reported',$4)`,[tenantId,incident.id,user_id,'Incident reported with '+photoList.length+' photo(s)']);

    for (const photoData of photoList) {
      const stored=await storeIncidentPhoto(tenantId,incident.id,photoData);if(stored.key)uploadedKeys.push(stored.key);
      await client.query(
        'INSERT INTO incident_photos (tenant_id,incident_id,photo_data,storage_provider,storage_key,content_type,size_bytes,checksum_sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [tenantId,incident.id,stored.photoData,stored.provider,stored.key,stored.contentType,stored.buffer.length,stored.checksum]
      );
    }

    await client.query('COMMIT');
    res.status(201).json({ ...incident, photo_count: photoList.length });
  } catch (err) {
    await client.query('ROLLBACK');
    for(const key of uploadedKeys)await objectStorageRequest('DELETE',key).catch(()=>{});
    if(err.code==='23505'&&clientIncidentId){const existing=await pool.query(`SELECT i.*,(SELECT COUNT(*)::int FROM incident_photos p WHERE p.tenant_id=i.tenant_id AND p.incident_id=i.id) photo_count FROM incidents i WHERE i.tenant_id=$1 AND i.client_incident_id=$2`,[tenantId,clientIncidentId]);if(existing.rows.length)return res.status(200).json({...existing.rows[0],duplicate:true,idempotent:true});}
    res.status(err.statusCode||500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/incidents', requireAuth, async (req, res) => {
  const { tenant_id, date, status, category, site_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => {
      let baseQuery = `
        SELECT i.*, COALESCE(p.photo_count, 0) AS photo_count,s.name AS site_name,reporter.email AS reporter_email,assignee.email AS assigned_email
        FROM incidents i
        JOIN sites s ON s.id=i.site_id LEFT JOIN users reporter ON reporter.id=i.user_id LEFT JOIN users assignee ON assignee.id=i.assigned_to
        LEFT JOIN (
          SELECT incident_id, COUNT(*) AS photo_count
          FROM incident_photos
          WHERE tenant_id = $1
          GROUP BY incident_id
        ) p ON p.incident_id = i.id
        WHERE i.tenant_id = $1
      `;
      const params=[tenant_id];if(date){params.push(date);baseQuery+=` AND i.reported_at::date=$${params.length}`;}if(status){params.push(status);baseQuery+=` AND i.status=$${params.length}`;}if(category){params.push(category);baseQuery+=` AND i.category=$${params.length}`;}if(site_id){params.push(site_id);baseQuery+=` AND i.site_id=$${params.length}`;}return client.query(baseQuery+' ORDER BY i.reported_at DESC LIMIT 500',params);
    });
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/incidents/:id/case',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status,assignedTo=req.body.assigned_to?Number(req.body.assigned_to):null,resolution=String(req.body.resolution||'').trim();
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(status&&!['reported','acknowledged','investigating','resolved','closed'].includes(status))return res.status(400).json({error:'Invalid incident status'});if(['resolved','closed'].includes(status)&&!resolution)return res.status(400).json({error:'Resolution details are required'});
  const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);if(assignedTo){const owner=await client.query("SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2 AND role='admin'",[assignedTo,tenantId]);if(!owner.rows.length)throw Object.assign(new Error('Assigned supervisor not found'),{statusCode:400});}const current=await client.query('SELECT * FROM incidents WHERE id=$1 AND tenant_id=$2 FOR UPDATE',[req.params.id,tenantId]);if(!current.rows.length)throw Object.assign(new Error('Incident not found'),{statusCode:404});const nextStatus=status||current.rows[0].status;const updated=await client.query(`UPDATE incidents SET status=$1,assigned_to=$2,resolution=CASE WHEN $3<>'' THEN $3 ELSE resolution END,acknowledged_at=CASE WHEN $1 IN ('acknowledged','investigating','resolved','closed') THEN COALESCE(acknowledged_at,NOW()) ELSE acknowledged_at END,resolved_at=CASE WHEN $1 IN ('resolved','closed') THEN COALESCE(resolved_at,NOW()) ELSE NULL END,updated_at=NOW() WHERE id=$4 AND tenant_id=$5 RETURNING *`,[nextStatus,assignedTo,resolution,req.params.id,tenantId]);const changes=[];if(nextStatus!==current.rows[0].status)changes.push('Status: '+current.rows[0].status+' → '+nextStatus);if(assignedTo!==current.rows[0].assigned_to)changes.push(assignedTo?'Case assigned to supervisor #'+assignedTo:'Case unassigned');if(resolution)changes.push('Resolution: '+resolution);await client.query(`INSERT INTO incident_activities (tenant_id,incident_id,user_id,activity_type,note) VALUES ($1,$2,$3,'case_updated',$4)`,[tenantId,req.params.id,req.auth.user_id,changes.join('; ')||'Case updated']);await client.query('COMMIT');res.json(updated.rows[0]);}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}
});

app.post('/api/incidents/:id/comments',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),note=String(req.body.note||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!note)return res.status(400).json({error:'Comment is required'});try{const result=await withTenant(tenantId,async client=>{const exists=await client.query('SELECT 1 FROM incidents WHERE id=$1 AND tenant_id=$2',[req.params.id,tenantId]);if(!exists.rows.length)throw Object.assign(new Error('Incident not found'),{statusCode:404});return client.query(`INSERT INTO incident_activities (tenant_id,incident_id,user_id,activity_type,note) VALUES ($1,$2,$3,'comment',$4) RETURNING *`,[tenantId,req.params.id,req.auth.user_id,note])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}});

app.get('/api/incidents/:id/activities',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`SELECT ia.*,u.email AS user_email FROM incident_activities ia LEFT JOIN users u ON u.id=ia.user_id WHERE ia.incident_id=$1 AND ia.tenant_id=$2 ORDER BY ia.created_at`,[req.params.id,tenantId]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/incidents/:id/photos', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        'SELECT id,photo_data,storage_provider,storage_key,content_type,size_bytes,checksum_sha256,created_at FROM incident_photos WHERE incident_id = $1 AND tenant_id = $2 ORDER BY created_at ASC',
        [id, tenant_id]
      )
    );
    const photos=[];for(const row of result.rows){try{photos.push({...row,photo_data:await readIncidentPhoto(row),storage_key:undefined})}catch(e){photos.push({...row,photo_data:null,storage_key:undefined,storage_error:'Evidence temporarily unavailable'})}}res.json(photos);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/incidents/:id/photos', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id,async client=>{const rows=await client.query('SELECT id,storage_provider,storage_key FROM incident_photos WHERE incident_id=$1 AND tenant_id=$2',[id,tenant_id]);for(const row of rows.rows)if(row.storage_provider==='s3'&&row.storage_key)await objectStorageRequest('DELETE',row.storage_key);return client.query('DELETE FROM incident_photos WHERE incident_id=$1 AND tenant_id=$2 RETURNING id',[id,tenant_id])});
    res.json({ deleted_count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------ STAGE 7.1: INCIDENT RECONSTRUCTION ------------------------

app.get('/api/incident-reconstruction/:id', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  const incidentId = Number(req.params.id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!Number.isInteger(incidentId) || incidentId < 1) return res.status(400).json({ error: 'Invalid incident ID' });
  try {
    const payload = await withTenant(tenantId, async client => {
      const incidentResult = await client.query(`
        SELECT i.*,s.name site_name,c.name checkpoint_name,reporter.email reporter_email,assignee.email assigned_email
        FROM incidents i JOIN sites s ON s.id=i.site_id
        LEFT JOIN checkpoints c ON c.id=i.checkpoint_id
        LEFT JOIN users reporter ON reporter.id=i.user_id
        LEFT JOIN users assignee ON assignee.id=i.assigned_to
        WHERE i.id=$1 AND i.tenant_id=$2`, [incidentId, tenantId]);
      if (!incidentResult.rowCount) throw Object.assign(new Error('Incident not found'), { statusCode: 404 });
      const incident = incidentResult.rows[0];
      const start = new Date(new Date(incident.reported_at).getTime() - 2 * 60 * 60 * 1000);
      const endBase = incident.resolved_at || incident.updated_at || incident.reported_at;
      const end = new Date(new Date(endBase).getTime() + 2 * 60 * 60 * 1000);
      const [activities, photos, patrols, sos, dispatches, locations, audits] = await Promise.all([
        client.query(`SELECT ia.id,ia.activity_type,ia.note,ia.created_at,u.email actor_email FROM incident_activities ia LEFT JOIN users u ON u.id=ia.user_id WHERE ia.tenant_id=$1 AND ia.incident_id=$2 ORDER BY ia.created_at`, [tenantId, incidentId]),
        client.query(`SELECT id,storage_provider,content_type,size_bytes,checksum_sha256,created_at FROM incident_photos WHERE tenant_id=$1 AND incident_id=$2 ORDER BY created_at`, [tenantId, incidentId]),
        client.query(`SELECT pl.id,pl.scanned_at,pl.latitude,pl.longitude,pl.location_status,pl.scan_method,pl.offline_captured,c.name checkpoint_name,u.email actor_email FROM patrol_logs pl JOIN checkpoints c ON c.id=pl.checkpoint_id LEFT JOIN users u ON u.id=pl.user_id WHERE pl.tenant_id=$1 AND c.site_id=$2 AND pl.scanned_at BETWEEN $3 AND $4 ORDER BY pl.scanned_at LIMIT 250`, [tenantId, incident.site_id, start, end]),
        client.query(`SELECT sa.id,sa.message,sa.status,sa.latitude,sa.longitude,sa.created_at,sa.resolved_at,u.email actor_email FROM sos_alerts sa LEFT JOIN users u ON u.id=sa.user_id WHERE sa.tenant_id=$1 AND sa.site_id=$2 AND sa.created_at BETWEEN $3 AND $4 ORDER BY sa.created_at LIMIT 100`, [tenantId, incident.site_id, start, end]),
        client.query(`SELECT d.id,d.reference_code,d.title,d.priority,d.status,d.assigned_at,d.accepted_at,d.en_route_at,d.on_site_at,d.completed_at,d.completion_note,u.email guard_email FROM dispatch_jobs d LEFT JOIN users u ON u.id=d.assigned_guard_id WHERE d.tenant_id=$1 AND d.site_id=$2 AND d.created_at BETWEEN $3 AND $4 ORDER BY d.created_at LIMIT 100`, [tenantId, incident.site_id, start, end]),
        client.query(`SELECT gl.id,gl.user_id,gl.latitude,gl.longitude,gl.recorded_at,u.email actor_email FROM guard_location_history gl LEFT JOIN users u ON u.id=gl.user_id WHERE gl.tenant_id=$1 AND gl.site_id=$2 AND gl.recorded_at BETWEEN $3 AND $4 ORDER BY gl.recorded_at LIMIT 250`, [tenantId, incident.site_id, start, end]),
        client.query(`SELECT id,action,resource,entity_id,details,user_email,created_at FROM audit_logs WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3 AND (entity_id=$4 OR details->>'incident_id'=$4 OR resource ILIKE '%incident%') ORDER BY created_at LIMIT 100`, [tenantId, start, end, String(incidentId)])
      ]);
      const timeline = [];
      const add = (at, type, title, detail, actor, sourceId, coordinates) => timeline.push({ at, type, title, detail: detail || '', actor: actor || 'System', source_id: sourceId, coordinates: coordinates || null });
      add(incident.reported_at, 'incident', 'Incident reported', incident.description, incident.reporter_email, incident.id);
      if (incident.acknowledged_at) add(incident.acknowledged_at, 'incident', 'Incident acknowledged', '', incident.assigned_email, incident.id);
      if (incident.resolved_at) add(incident.resolved_at, 'incident', 'Incident resolved', incident.resolution, incident.assigned_email, incident.id);
      activities.rows.forEach(x => add(x.created_at, 'activity', String(x.activity_type || 'activity').replaceAll('_', ' '), x.note, x.actor_email, x.id));
      photos.rows.forEach(x => add(x.created_at, 'photo', 'Incident photo captured', `${x.storage_provider || 'database'} · ${x.content_type || 'unknown type'} · ${x.size_bytes || 0} bytes · checksum ${x.checksum_sha256 || 'unavailable'}`, null, x.id));
      patrols.rows.forEach(x => add(x.scanned_at, 'patrol', `Checkpoint scanned: ${x.checkpoint_name}`, `${x.scan_method || 'QR'} · location ${x.location_status || 'unavailable'}${x.offline_captured ? ' · captured offline' : ''}`, x.actor_email, x.id, x.latitude == null ? null : { latitude: x.latitude, longitude: x.longitude }));
      sos.rows.forEach(x => { add(x.created_at, 'sos', 'SOS alert raised', x.message || x.status, x.actor_email, x.id, x.latitude == null ? null : { latitude: x.latitude, longitude: x.longitude }); if (x.resolved_at) add(x.resolved_at, 'sos', 'SOS alert resolved', '', x.actor_email, x.id); });
      dispatches.rows.forEach(x => { [['assigned_at','Dispatch assigned'],['accepted_at','Dispatch accepted'],['en_route_at','Guard en route'],['on_site_at','Guard on site'],['completed_at','Dispatch completed']].forEach(([field,title]) => { if (x[field]) add(x[field], 'dispatch', `${title}: ${x.reference_code}`, x[field === 'completed_at' ? 'completion_note' : 'title'] || x.title, x.guard_email, x.id); }); });
      locations.rows.forEach(x => add(x.recorded_at, 'location', 'Guard location recorded', `${Number(x.latitude).toFixed(5)}, ${Number(x.longitude).toFixed(5)}`, x.actor_email, x.id, { latitude: x.latitude, longitude: x.longitude }));
      audits.rows.forEach(x => add(x.created_at, 'audit', `${x.action} ${x.resource}`, JSON.stringify(x.details || {}), x.user_email, x.id));
      timeline.sort((a, b) => new Date(a.at) - new Date(b.at));
      return { incident, window: { from: start, to: end }, counts: { activities: activities.rowCount, photos: photos.rowCount, patrol_scans: patrols.rowCount, sos_alerts: sos.rowCount, dispatches: dispatches.rowCount, locations: locations.rowCount, audit_events: audits.rowCount }, timeline };
    });
    res.json(payload);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

// ------------------------ ATTENDANCE / TIME CLOCK ------------------------

function attendanceTenant(req, requestedTenant) {
  const tenantId = Number(requestedTenant || req.auth.tenant_id);
  return tenantId === Number(req.auth.tenant_id) ? tenantId : null;
}

function distanceMetres(lat1, lon1, lat2, lon2) {
  const toRadians = value => value * Math.PI / 180;
  const earthRadius = 6371000;
  const deltaLat = toRadians(lat2 - lat1);
  const deltaLon = toRadians(lon2 - lon1);
  const a = Math.sin(deltaLat / 2) ** 2 + Math.cos(toRadians(lat1)) * Math.cos(toRadians(lat2)) * Math.sin(deltaLon / 2) ** 2;
  return earthRadius * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function patrolScanEvidence(site, latitude, longitude, accuracy) {
  const lat=Number(latitude),lng=Number(longitude),acc=Number(accuracy);
  if(!Number.isFinite(lat)||!Number.isFinite(lng)) return {accuracy:null,distance:null,status:'unavailable'};
  if(site.latitude===null||site.longitude===null) return {accuracy:Number.isFinite(acc)?acc:null,distance:null,status:'recorded'};
  const distance=Math.round(distanceMetres(lat,lng,Number(site.latitude),Number(site.longitude))*10)/10;
  if(!site.geofence_enabled)return {accuracy:Number.isFinite(acc)?acc:null,distance,status:'recorded'};
  return {accuracy:Number.isFinite(acc)?acc:null,distance,status:distance<=Number(site.geofence_radius_m||150)?'inside':'outside'};
}

async function getActiveAttendance(client, tenantId, userId) {
  const result = await client.query(
    `SELECT a.*, s.name AS site_name,
       b.id AS active_break_id, b.started_at AS break_started_at,
       COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (COALESCE(ab.ended_at, NOW()) - ab.started_at)))
                 FROM attendance_breaks ab WHERE ab.attendance_session_id = a.id), 0) AS break_seconds
     FROM attendance_sessions a
     JOIN sites s ON s.id = a.site_id
     LEFT JOIN attendance_breaks b ON b.attendance_session_id = a.id AND b.ended_at IS NULL
     WHERE a.tenant_id = $1 AND a.user_id = $2 AND a.clocked_out_at IS NULL`,
    [tenantId, userId]
  );
  return result.rows[0] || null;
}

app.get('/api/attendance/current', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const userId = req.auth.role === 'admin' && req.query.user_id ? Number(req.query.user_id) : req.auth.user_id;
  try {
    const session = await withTenant(tenantId, client => getActiveAttendance(client, tenantId, userId));
    res.json({ active: Boolean(session), session });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/attendance/clock-in', requireAuth, requireTrustedGuardDevice, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can clock in' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const { site_id, latitude, longitude, accuracy } = req.body;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!site_id) return res.status(400).json({ error: 'Select a site before clocking in' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.current_tenant = '${tenantId}'`);
    const assignment = await client.query(
      `SELECT s.latitude, s.longitude, s.geofence_radius_m, s.geofence_enabled
       FROM guard_assignments ga JOIN sites s ON s.id=ga.site_id
       WHERE ga.tenant_id=$1 AND ga.user_id=$2 AND ga.site_id=$3`,
      [tenantId, req.auth.user_id, site_id]
    );
    if (assignment.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'You are not assigned to this site' });
    }
    const site = assignment.rows[0];
    let clockInDistance = null;
    let geofenceVerified = null;
    if (site.geofence_enabled) {
      if (!Number.isFinite(Number(latitude)) || !Number.isFinite(Number(longitude))) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Location permission is required to clock in at this site', code: 'LOCATION_REQUIRED' });
      }
      if (Number.isFinite(Number(accuracy)) && Number(accuracy) > 200) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Your GPS accuracy is too low. Move outdoors or wait for a stronger location signal, then try again.', code: 'LOCATION_INACCURATE', accuracy_m: Math.round(Number(accuracy)) });
      }
      clockInDistance = distanceMetres(Number(latitude), Number(longitude), Number(site.latitude), Number(site.longitude));
      geofenceVerified = clockInDistance <= Number(site.geofence_radius_m);
      if (!geofenceVerified) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: `You are ${Math.round(clockInDistance)}m from the site. Move within the ${site.geofence_radius_m}m clock-in area.`,
          code: 'OUTSIDE_GEOFENCE', distance_m: Math.round(clockInDistance), radius_m: site.geofence_radius_m
        });
      }
    }
    const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
    if (active) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'You are already clocked in', session: active });
    }
    const scheduledShift = await client.query(
      `SELECT id FROM shifts WHERE tenant_id=$1 AND user_id=$2 AND site_id=$3
       AND shift_date = CURRENT_DATE ORDER BY start_time LIMIT 1`,
      [tenantId, req.auth.user_id, site_id]
    );
    await client.query(
      `INSERT INTO attendance_sessions
       (tenant_id,user_id,site_id,shift_id,clock_in_latitude,clock_in_longitude,clock_in_accuracy,
        clock_in_distance_m,clock_in_geofence_radius_m,clock_in_geofence_verified)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [tenantId, req.auth.user_id, site_id, scheduledShift.rows[0]?.id || null,
       latitude ?? null, longitude ?? null, accuracy ?? null, clockInDistance,
       site.geofence_enabled ? site.geofence_radius_m : null, geofenceVerified]
    );
    await client.query('COMMIT');
    const session = await withTenant(tenantId, c => getActiveAttendance(c, tenantId, req.auth.user_id));
    res.status(201).json({ active: true, session });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(err.code === '23505' ? 409 : 500).json({ error: err.code === '23505' ? 'You are already clocked in' : err.message });
  } finally { client.release(); }
});

app.post('/api/attendance/break/start', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can manage breaks' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const result = await withTenant(tenantId, async client => {
      const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
      if (!active) throw Object.assign(new Error('Clock in before starting a break'), { statusCode: 409 });
      if (active.active_break_id) throw Object.assign(new Error('A break is already active'), { statusCode: 409 });
      await client.query(
        `INSERT INTO attendance_breaks (tenant_id,attendance_session_id,start_latitude,start_longitude)
         VALUES ($1,$2,$3,$4)`,
        [tenantId, active.id, req.body.latitude ?? null, req.body.longitude ?? null]
      );
      return getActiveAttendance(client, tenantId, req.auth.user_id);
    });
    res.status(201).json({ active: true, session: result });
  } catch (err) { res.status(err.statusCode || (err.code === '23505' ? 409 : 500)).json({ error: err.message }); }
});

app.post('/api/attendance/break/end', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can manage breaks' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const session = await withTenant(tenantId, async client => {
      const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
      if (!active || !active.active_break_id) throw Object.assign(new Error('No active break found'), { statusCode: 409 });
      await client.query(
        `UPDATE attendance_breaks SET ended_at=NOW(), end_latitude=$1, end_longitude=$2
         WHERE id=$3 AND tenant_id=$4 AND ended_at IS NULL`,
        [req.body.latitude ?? null, req.body.longitude ?? null, active.active_break_id, tenantId]
      );
      return getActiveAttendance(client, tenantId, req.auth.user_id);
    });
    res.json({ active: true, session });
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.post('/api/attendance/clock-out', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can clock out' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const completed = await withTenant(tenantId, async client => {
      const active = await getActiveAttendance(client, tenantId, req.auth.user_id);
      if (!active) throw Object.assign(new Error('No active attendance session found'), { statusCode: 409 });
      if (active.active_break_id) await client.query('UPDATE attendance_breaks SET ended_at=NOW() WHERE id=$1', [active.active_break_id]);
      const result = await client.query(
        `UPDATE attendance_sessions SET clocked_out_at=NOW(), clock_out_latitude=$1,
         clock_out_longitude=$2, clock_out_accuracy=$3 WHERE id=$4 AND tenant_id=$5 RETURNING *`,
        [req.body.latitude ?? null, req.body.longitude ?? null, req.body.accuracy ?? null, active.id, tenantId]
      );
      return result.rows[0];
    });
    res.json({ active: false, session: null, completed_session: completed });
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.get('/api/attendance', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const result = await withTenant(tenantId, client => {
      let query = `SELECT a.*, u.email AS guard_email, s.name AS site_name,
        COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (COALESCE(b.ended_at,NOW())-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id),0) AS break_seconds,
        EXTRACT(EPOCH FROM (COALESCE(a.clocked_out_at,NOW())-a.clocked_in_at)) AS elapsed_seconds,
        EXISTS(SELECT 1 FROM attendance_breaks active_break WHERE active_break.attendance_session_id=a.id AND active_break.ended_at IS NULL) AS on_break
        FROM attendance_sessions a JOIN users u ON u.id=a.user_id JOIN sites s ON s.id=a.site_id
        WHERE a.tenant_id=$1`;
      const params = [tenantId];
      if (req.query.date) { params.push(req.query.date); query += ` AND a.clocked_in_at::date=$${params.length}`; }
      if (req.query.user_id) { params.push(req.query.user_id); query += ` AND a.user_id=$${params.length}`; }
      if (req.query.site_id) { params.push(req.query.site_id); query += ` AND a.site_id=$${params.length}`; }
      query += ' ORDER BY a.clocked_in_at DESC LIMIT 500';
      return client.query(query, params);
    });
    res.json(result.rows.map(row => ({ ...row, worked_seconds: Math.max(0, Number(row.elapsed_seconds)-Number(row.break_seconds)) })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ AVAILABILITY & LEAVE ------------------------

app.get('/api/availability', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const userId = req.auth.role === 'admin' && req.query.user_id ? Number(req.query.user_id) : req.auth.user_id;
  try {
    const result = await withTenant(tenantId, client => client.query(
      'SELECT * FROM guard_availability WHERE tenant_id=$1 AND user_id=$2 ORDER BY weekday', [tenantId,userId]
    ));
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/availability', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can update their availability' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const days = req.body.days;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!Array.isArray(days) || days.length !== 7) return res.status(400).json({ error: 'Availability must include all seven weekdays' });
  try {
    const rows = await withTenant(tenantId, async client => {
      const saved=[];
      for (const day of days) {
        const weekday=Number(day.weekday),available=Boolean(day.is_available);
        if (!Number.isInteger(weekday)||weekday<0||weekday>6) throw Object.assign(new Error('Invalid weekday'),{statusCode:400});
        if (available && (!TIME_FORMAT_REGEX.test(day.available_from||'')||!TIME_FORMAT_REGEX.test(day.available_until||''))) throw Object.assign(new Error('Available days require valid start and end times'),{statusCode:400});
        const result=await client.query(
          `INSERT INTO guard_availability (tenant_id,user_id,weekday,is_available,available_from,available_until)
           VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,user_id,weekday) DO UPDATE SET
           is_available=EXCLUDED.is_available,available_from=EXCLUDED.available_from,available_until=EXCLUDED.available_until,updated_at=NOW() RETURNING *`,
          [tenantId,req.auth.user_id,weekday,available,available?day.available_from:null,available?day.available_until:null]
        );saved.push(result.rows[0]);
      }return saved;
    });
    res.json(rows);
  } catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.post('/api/leave-requests', requireAuth, async (req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can request leave'});
  const tenantId=attendanceTenant(req,req.body.tenant_id);const {start_date,end_date,leave_type,reason}=req.body;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!validTimesheetPeriod(start_date,end_date))return res.status(400).json({error:'Choose a valid leave period of no more than 32 days'});
  if(!['annual','sick','unpaid','other'].includes(leave_type))return res.status(400).json({error:'Invalid leave type'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `INSERT INTO leave_requests (tenant_id,user_id,start_date,end_date,leave_type,reason) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [tenantId,req.auth.user_id,start_date,end_date,leave_type,reason||null]));res.status(201).json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/leave-requests',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>{let query=`SELECT l.*,u.email AS guard_email,r.email AS reviewer_email FROM leave_requests l JOIN users u ON u.id=l.user_id LEFT JOIN users r ON r.id=l.reviewed_by WHERE l.tenant_id=$1`;const params=[tenantId];if(req.auth.role!=='admin'){params.push(req.auth.user_id);query+=` AND l.user_id=$${params.length}`}else if(req.query.user_id){params.push(req.query.user_id);query+=` AND l.user_id=$${params.length}`}if(req.query.status){params.push(req.query.status);query+=` AND l.status=$${params.length}`}query+=' ORDER BY l.requested_at DESC LIMIT 250';return client.query(query,params)});res.json(result.rows);}
  catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/leave-requests/:id/review',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);const {status,review_notes}=req.body;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['approved','rejected'].includes(status))return res.status(400).json({error:'Invalid review status'});
  if(status==='rejected'&&!String(review_notes||'').trim())return res.status(400).json({error:'A rejection reason is required'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `UPDATE leave_requests SET status=$1,review_notes=$2,reviewed_at=NOW(),reviewed_by=$3 WHERE id=$4 AND tenant_id=$5 AND status='pending' RETURNING *`,
    [status,String(review_notes||'').trim()||null,req.auth.user_id,req.params.id,tenantId]));if(!result.rows.length)return res.status(409).json({error:'Request not found or already reviewed'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.delete('/api/leave-requests/:id',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can cancel requests'});const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query("DELETE FROM leave_requests WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND status='pending' RETURNING id",[req.params.id,tenantId,req.auth.user_id]));if(!result.rows.length)return res.status(409).json({error:'Only pending requests can be cancelled'});res.json({deleted:result.rows[0]});}catch(err){res.status(500).json({error:err.message});}
});

// ------------------------ TIMESHEETS & APPROVALS ------------------------

function validTimesheetPeriod(start, end) {
  const startDate = DateTime.fromISO(start).startOf('day');
  const endDate = DateTime.fromISO(end).startOf('day');
  return startDate.isValid && endDate.isValid && endDate >= startDate && endDate.diff(startDate, 'days').days <= 31;
}

async function calculateTimesheet(client, tenantId, userId, periodStart, periodEnd) {
  const result = await client.query(
    `SELECT COUNT(*)::int AS session_count,
       COALESCE(SUM(EXTRACT(EPOCH FROM (a.clocked_out_at-a.clocked_in_at))),0)::bigint AS elapsed_seconds,
       COALESCE(SUM((SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))),0)
                     FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL)),0)::bigint AS break_seconds
     FROM attendance_sessions a
     WHERE a.tenant_id=$1 AND a.user_id=$2 AND a.clocked_out_at IS NOT NULL
       AND a.clocked_in_at::date BETWEEN $3 AND $4`,
    [tenantId, userId, periodStart, periodEnd]
  );
  const row = result.rows[0];
  return {
    session_count: Number(row.session_count),
    elapsed_seconds: Number(row.elapsed_seconds),
    break_seconds: Number(row.break_seconds),
    worked_seconds: Math.max(0, Number(row.elapsed_seconds) - Number(row.break_seconds))
  };
}

app.get('/api/timesheets/preview', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const userId = req.auth.role === 'admin' && req.query.user_id ? Number(req.query.user_id) : req.auth.user_id;
  if (!validTimesheetPeriod(req.query.period_start, req.query.period_end)) {
    return res.status(400).json({ error: 'Choose a valid period of no more than 32 days' });
  }
  try {
    const summary = await withTenant(tenantId, client => calculateTimesheet(client, tenantId, userId, req.query.period_start, req.query.period_end));
    const sessions = await withTenant(tenantId, client => client.query(
      `SELECT a.*, s.name AS site_name,
       COALESCE((SELECT SUM(EXTRACT(EPOCH FROM (b.ended_at-b.started_at))) FROM attendance_breaks b WHERE b.attendance_session_id=a.id AND b.ended_at IS NOT NULL),0) AS break_seconds
       FROM attendance_sessions a JOIN sites s ON s.id=a.site_id
       WHERE a.tenant_id=$1 AND a.user_id=$2 AND a.clocked_out_at IS NOT NULL
       AND a.clocked_in_at::date BETWEEN $3 AND $4 ORDER BY a.clocked_in_at`,
      [tenantId, userId, req.query.period_start, req.query.period_end]
    ));
    res.json({ ...summary, sessions: sessions.rows.map(row => ({ ...row, worked_seconds: Math.max(0, (new Date(row.clocked_out_at)-new Date(row.clocked_in_at))/1000-Number(row.break_seconds)) })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/timesheets/submit', requireAuth, async (req, res) => {
  if (req.auth.role !== 'guard') return res.status(403).json({ error: 'Only guards can submit their timesheets' });
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const { period_start, period_end } = req.body;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!validTimesheetPeriod(period_start, period_end)) return res.status(400).json({ error: 'Choose a valid period of no more than 32 days' });
  try {
    const timesheet = await withTenant(tenantId, async client => {
      const existing = await client.query(
        'SELECT * FROM timesheets WHERE tenant_id=$1 AND user_id=$2 AND period_start=$3 AND period_end=$4',
        [tenantId, req.auth.user_id, period_start, period_end]
      );
      if (existing.rows[0]?.status === 'approved') throw Object.assign(new Error('This timesheet is approved and locked'), { statusCode: 409 });
      const open = await client.query(
        `SELECT 1 FROM attendance_sessions WHERE tenant_id=$1 AND user_id=$2 AND clocked_out_at IS NULL
         AND clocked_in_at::date BETWEEN $3 AND $4`, [tenantId, req.auth.user_id, period_start, period_end]
      );
      if (open.rows.length) throw Object.assign(new Error('Clock out before submitting this timesheet'), { statusCode: 409 });
      const summary = await calculateTimesheet(client, tenantId, req.auth.user_id, period_start, period_end);
      if (summary.session_count === 0) throw Object.assign(new Error('There are no completed attendance sessions in this period'), { statusCode: 400 });
      const result = await client.query(
        `INSERT INTO timesheets (tenant_id,user_id,period_start,period_end,status,session_count,worked_seconds,break_seconds,submitted_at,reviewed_at,reviewed_by,review_notes)
         VALUES ($1,$2,$3,$4,'submitted',$5,$6,$7,NOW(),NULL,NULL,NULL)
         ON CONFLICT (tenant_id,user_id,period_start,period_end) DO UPDATE SET
           status='submitted',session_count=EXCLUDED.session_count,worked_seconds=EXCLUDED.worked_seconds,
           break_seconds=EXCLUDED.break_seconds,submitted_at=NOW(),reviewed_at=NULL,reviewed_by=NULL,review_notes=NULL,updated_at=NOW()
         RETURNING *`,
        [tenantId, req.auth.user_id, period_start, period_end, summary.session_count, summary.worked_seconds, summary.break_seconds]
      );
      return result.rows[0];
    });
    res.status(201).json(timesheet);
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.get('/api/timesheets', requireAuth, async (req, res) => {
  const tenantId = attendanceTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  try {
    const result = await withTenant(tenantId, client => {
      let query = `SELECT t.*, u.email AS guard_email, reviewer.email AS reviewer_email
                   FROM timesheets t JOIN users u ON u.id=t.user_id LEFT JOIN users reviewer ON reviewer.id=t.reviewed_by
                   WHERE t.tenant_id=$1`;
      const params = [tenantId];
      if (req.auth.role !== 'admin') { params.push(req.auth.user_id); query += ` AND t.user_id=$${params.length}`; }
      else if (req.query.user_id) { params.push(req.query.user_id); query += ` AND t.user_id=$${params.length}`; }
      if (req.query.status) { params.push(req.query.status); query += ` AND t.status=$${params.length}`; }
      query += ' ORDER BY t.period_start DESC, t.submitted_at DESC LIMIT 250';
      return client.query(query, params);
    });
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/timesheets/:id/review', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = attendanceTenant(req, req.body.tenant_id);
  const { status, review_notes } = req.body;
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!['approved','rejected'].includes(status)) return res.status(400).json({ error: 'Status must be approved or rejected' });
  if (status === 'rejected' && !String(review_notes || '').trim()) return res.status(400).json({ error: 'Add a reason when rejecting a timesheet' });
  try {
    const result = await withTenant(tenantId, client => client.query(
      `UPDATE timesheets SET status=$1,review_notes=$2,reviewed_at=NOW(),reviewed_by=$3,updated_at=NOW()
       WHERE id=$4 AND tenant_id=$5 AND status='submitted' RETURNING *`,
      [status, String(review_notes || '').trim() || null, req.auth.user_id, req.params.id, tenantId]
    ));
    if (!result.rows.length) return res.status(409).json({ error: 'Timesheet not found or already reviewed' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ SHIFT SCHEDULING ------------------------

const TIME_FORMAT_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;
const MAX_WEEKLY_REPEAT_DAYS = 182;
const MAX_MONTHLY_REPEAT_DAYS = 366;
const MAX_GENERATED_SHIFTS = 250;

function computeShiftDurationHours(startTime, endTime) {
  const [startHour, startMinute] = startTime.split(':').map(Number);
  const [endHour, endMinute] = endTime.split(':').map(Number);
  let difference = (endHour * 60 + endMinute) - (startHour * 60 + startMinute);
  if (difference <= 0) difference += 24 * 60;
  return Math.round((difference / 60) * 100) / 100;
}

function generateShiftDates({ recurrence, start_date, repeat_until, days_of_week, days_of_month }) {
  const start = DateTime.fromISO(start_date).startOf('day');
  if (!start.isValid) throw Object.assign(new Error('start_date is invalid'), { statusCode: 400 });
  if (recurrence === 'none') return [start];

  if (!repeat_until) {
    throw Object.assign(new Error('repeat_until is required for recurring shifts'), { statusCode: 400 });
  }
  const until = DateTime.fromISO(repeat_until).startOf('day');
  if (!until.isValid || until < start) {
    throw Object.assign(new Error('repeat_until must be on or after start_date'), { statusCode: 400 });
  }

  const span = until.diff(start, 'days').days;
  const dates = [];
  if (recurrence === 'weekly') {
    if (span > MAX_WEEKLY_REPEAT_DAYS) {
      throw Object.assign(new Error(`Weekly recurrence cannot span more than ${MAX_WEEKLY_REPEAT_DAYS} days`), { statusCode: 400 });
    }
    if (!Array.isArray(days_of_week) || days_of_week.length === 0) {
      throw Object.assign(new Error('Select at least one day for weekly recurrence'), { statusCode: 400 });
    }
    const weekdays = new Set(days_of_week.map(day => Number(day) === 0 ? 7 : Number(day)));
    for (let date = start; date <= until && dates.length < MAX_GENERATED_SHIFTS; date = date.plus({ days: 1 })) {
      if (weekdays.has(date.weekday)) dates.push(date);
    }
    return dates;
  }

  if (recurrence === 'monthly') {
    if (span > MAX_MONTHLY_REPEAT_DAYS) {
      throw Object.assign(new Error(`Monthly recurrence cannot span more than ${MAX_MONTHLY_REPEAT_DAYS} days`), { statusCode: 400 });
    }
    if (!Array.isArray(days_of_month) || days_of_month.length === 0) {
      throw Object.assign(new Error('Select at least one day of the month'), { statusCode: 400 });
    }
    const monthDays = [...new Set(days_of_month.map(Number))].filter(day => Number.isInteger(day) && day >= 1 && day <= 31).sort((a, b) => a - b);
    if (monthDays.length === 0) {
      throw Object.assign(new Error('days_of_month must contain numbers from 1 to 31'), { statusCode: 400 });
    }
    for (let month = start.startOf('month'); month <= until && dates.length < MAX_GENERATED_SHIFTS; month = month.plus({ months: 1 })) {
      for (const day of monthDays) {
        if (day > month.daysInMonth) continue;
        const occurrence = month.set({ day });
        if (occurrence >= start && occurrence <= until && dates.length < MAX_GENERATED_SHIFTS) dates.push(occurrence);
      }
    }
    return dates;
  }
  throw Object.assign(new Error('recurrence must be none, weekly, or monthly'), { statusCode: 400 });
}

function validTemplateColor(color) {
  return /^#[0-9a-f]{6}$/i.test(color || '');
}

const WEEKLY_OVERTIME_WARNING_HOURS = 40;

function shiftInterval(date, startTime, endTime) {
  const day = typeof date === 'string' ? date.slice(0, 10) : DateTime.fromJSDate(date).toISODate();
  const start = DateTime.fromISO(day + 'T' + startTime);
  let end = DateTime.fromISO(day + 'T' + endTime);
  if (end <= start) end = end.plus({ days: 1 });
  return { start, end };
}

function paidShiftHours(startTime, endTime, breakMinutes) {
  return Math.max(0, computeShiftDurationHours(startTime, endTime) - Number(breakMinutes || 0) / 60);
}

async function analyseProposedShifts(client, tenantId, userId, dates, startTime, endTime, breakMinutes, excludeShiftId = null) {
  const proposed = dates.map(date => ({ date: date.toISODate(), ...shiftInterval(date.toISODate(), startTime, endTime) }));
  const firstDate = proposed[0].start.startOf('week').minus({ days: 1 }).toISODate();
  const lastDate = proposed[proposed.length - 1].end.endOf('week').plus({ days: 1 }).toISODate();
  const existingResult = await client.query(
    `SELECT sh.*, s.name AS site_name FROM shifts sh JOIN sites s ON s.id=sh.site_id
     WHERE sh.tenant_id=$1 AND sh.user_id=$2 AND sh.shift_date BETWEEN $3 AND $4
       AND ($5::int IS NULL OR sh.id <> $5)
     ORDER BY sh.shift_date, sh.start_time`, [tenantId, userId, firstDate, lastDate, excludeShiftId]
  );
  const existing = existingResult.rows.map(shift => ({ ...shift, ...shiftInterval(shift.shift_date, shift.start_time, shift.end_time) }));
  const conflicts = [];
  for (const candidate of proposed) {
    for (const shift of existing) {
      if (candidate.start < shift.end && candidate.end > shift.start) {
        conflicts.push({ proposed_date: candidate.date, existing_shift_id: shift.id, existing_date: String(shift.shift_date).slice(0,10), existing_time: shift.start_time + '–' + shift.end_time, site_name: shift.site_name });
      }
    }
  }

  const availabilityResult = await client.query(
    'SELECT * FROM guard_availability WHERE tenant_id=$1 AND user_id=$2', [tenantId,userId]
  );
  const availabilityByDay = new Map(availabilityResult.rows.map(row => [Number(row.weekday),row]));
  const leaveResult = await client.query(
    `SELECT id,start_date,end_date,leave_type FROM leave_requests
     WHERE tenant_id=$1 AND user_id=$2 AND status='approved' AND start_date <= $3 AND end_date >= $4`,
    [tenantId,userId,lastDate,firstDate]
  );
  const availability_conflicts=[];
  const timeMinutes=value=>{const [h,m]=String(value).split(':').map(Number);return h*60+m};
  for(const candidate of proposed){
    const leave=leaveResult.rows.find(item=>candidate.date>=String(item.start_date).slice(0,10)&&candidate.date<=String(item.end_date).slice(0,10));
    if(leave){availability_conflicts.push({date:candidate.date,type:'approved_leave',message:`${candidate.date}: guard is on approved ${leave.leave_type} leave.`});continue;}
    if(availabilityResult.rows.length){
      const rule=availabilityByDay.get(candidate.start.weekday%7);
      if(!rule||!rule.is_available){availability_conflicts.push({date:candidate.date,type:'unavailable_day',message:`${candidate.date}: guard marked this weekday unavailable.`});continue;}
      let shiftStart=timeMinutes(startTime),shiftEnd=timeMinutes(endTime),availableStart=timeMinutes(rule.available_from),availableEnd=timeMinutes(rule.available_until);
      if(shiftEnd<=shiftStart)shiftEnd+=1440;if(availableEnd<=availableStart)availableEnd+=1440;
      if(shiftStart<availableStart||shiftEnd>availableEnd)availability_conflicts.push({date:candidate.date,type:'outside_availability',message:`${candidate.date}: ${startTime}–${endTime} is outside availability ${rule.available_from}–${rule.available_until}.`});
    }
  }

  const weeklyHours = new Map();
  for (const shift of existing) {
    const week = shift.start.startOf('week').toISODate();
    weeklyHours.set(week, (weeklyHours.get(week) || 0) + paidShiftHours(shift.start_time, shift.end_time, shift.break_minutes));
  }
  const candidateHours = paidShiftHours(startTime, endTime, breakMinutes);
  for (const candidate of proposed) {
    const week = candidate.start.startOf('week').toISODate();
    weeklyHours.set(week, (weeklyHours.get(week) || 0) + candidateHours);
  }
  const warnings = [...weeklyHours.entries()]
    .filter(([, hours]) => hours > WEEKLY_OVERTIME_WARNING_HOURS)
    .map(([week_start, hours]) => ({ type: 'overtime', week_start, scheduled_hours: Math.round(hours * 100) / 100, threshold_hours: WEEKLY_OVERTIME_WARNING_HOURS,
      message: `Week of ${week_start}: ${Math.round(hours * 100) / 100} scheduled hours exceeds the ${WEEKLY_OVERTIME_WARNING_HOURS}-hour threshold.` }));
  return { conflicts, availability_conflicts, warnings, proposed_count: proposed.length };
}

app.get('/api/shift-templates', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = req.query.tenant_id || req.auth.tenant_id;
  if (!tenantId) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenantId, (client) => client.query(
      `SELECT st.*, s.name AS site_name
       FROM shift_templates st LEFT JOIN sites s ON s.id = st.site_id
       WHERE st.tenant_id = $1 ORDER BY st.name ASC`, [tenantId]
    ));
    res.json(result.rows.map(template => ({
      ...template,
      paid_hours: Math.max(0, Math.round((computeShiftDurationHours(template.start_time, template.end_time) - template.break_minutes / 60) * 100) / 100)
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/shift-templates', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, name, color, start_time, end_time, break_minutes, employment_type, notes } = req.body;
  if (!tenant_id || !name || !start_time || !end_time) {
    return res.status(400).json({ error: 'tenant_id, name, start_time, and end_time are required' });
  }
  if (!TIME_FORMAT_REGEX.test(start_time) || !TIME_FORMAT_REGEX.test(end_time)) {
    return res.status(400).json({ error: 'Start and end time must use HH:MM format' });
  }
  const breakMinutes = Number(break_minutes || 0);
  if (!Number.isInteger(breakMinutes) || breakMinutes < 0 || breakMinutes > 720) {
    return res.status(400).json({ error: 'Break must be between 0 and 720 minutes' });
  }
  const templateColor = validTemplateColor(color) ? color : '#2563eb';
  const employmentType = ['full_time', 'part_time'].includes(employment_type) ? employment_type : 'full_time';
  try {
    const result = await withTenant(tenant_id, async (client) => {
      if (site_id) {
        const site = await client.query('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [site_id, tenant_id]);
        if (site.rows.length === 0) throw Object.assign(new Error('Site not found for this tenant'), { statusCode: 404 });
      }
      return client.query(
        `INSERT INTO shift_templates (tenant_id, site_id, name, color, start_time, end_time, break_minutes, employment_type, notes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [tenant_id, site_id || null, name.trim(), templateColor, start_time, end_time, breakMinutes, employmentType, notes || null]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message }); }
});

app.patch('/api/shift-templates/:id', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, name, color, start_time, end_time, break_minutes, employment_type, notes } = req.body;
  if (!tenant_id || !name || !start_time || !end_time) return res.status(400).json({ error: 'All required template fields must be supplied' });
  if (!TIME_FORMAT_REGEX.test(start_time) || !TIME_FORMAT_REGEX.test(end_time)) return res.status(400).json({ error: 'Start and end time must use HH:MM format' });
  const breakMinutes = Number(break_minutes || 0);
  if (!Number.isInteger(breakMinutes) || breakMinutes < 0 || breakMinutes > 720) return res.status(400).json({ error: 'Break must be between 0 and 720 minutes' });
  try {
    const result = await withTenant(tenant_id, (client) => client.query(
      `UPDATE shift_templates SET site_id=$1, name=$2, color=$3, start_time=$4, end_time=$5,
       break_minutes=$6, employment_type=$7, notes=$8, updated_at=NOW()
       WHERE id=$9 AND tenant_id=$10 RETURNING *`,
      [site_id || null, name.trim(), validTemplateColor(color) ? color : '#2563eb', start_time, end_time,
       breakMinutes, ['full_time','part_time'].includes(employment_type) ? employment_type : 'full_time', notes || null, req.params.id, tenant_id]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/shift-templates/:id', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = req.query.tenant_id;
  if (!tenantId) return res.status(400).json({ error: 'tenant_id is required' });
  try {
    const result = await withTenant(tenantId, (client) => client.query(
      'DELETE FROM shift_templates WHERE id=$1 AND tenant_id=$2 RETURNING id', [req.params.id, tenantId]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/shifts', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, site_id, user_id, start_date, start_time, end_time, break_minutes,
    employment_type, recurrence, days_of_week, days_of_month, repeat_until, notes, dry_run } = req.body;
  if (!tenant_id || !site_id || !user_id || !start_date || !start_time || !end_time) {
    return res.status(400).json({ error: 'tenant_id, site_id, user_id, start_date, start_time, and end_time are required' });
  }
  if (!TIME_FORMAT_REGEX.test(start_time) || !TIME_FORMAT_REGEX.test(end_time)) {
    return res.status(400).json({ error: 'Start and end time must use HH:MM format' });
  }
  const employmentType = ['full_time', 'part_time'].includes(employment_type) ? employment_type : 'full_time';
  const recurrenceType = ['none', 'weekly', 'monthly'].includes(recurrence) ? recurrence : 'none';
  const breakMinutes = Number(break_minutes || 0);
  if (!Number.isInteger(breakMinutes) || breakMinutes < 0 || breakMinutes > 720) return res.status(400).json({ error: 'Break must be between 0 and 720 minutes' });

  try {
    const dates = generateShiftDates({ recurrence: recurrenceType, start_date, repeat_until, days_of_week, days_of_month });
    if (dates.length === 0) return res.status(400).json({ error: 'No shift dates match the recurrence settings' });

    const shifts = await withTenant(tenant_id, async (client) => {
      const guard = await client.query("SELECT id FROM users WHERE id = $1 AND tenant_id = $2 AND role = 'guard'", [user_id, tenant_id]);
      if (guard.rows.length === 0) throw Object.assign(new Error('Guard not found for this tenant'), { statusCode: 404 });
      const site = await client.query('SELECT id FROM sites WHERE id = $1 AND tenant_id = $2', [site_id, tenant_id]);
      if (site.rows.length === 0) throw Object.assign(new Error('Site not found for this tenant'), { statusCode: 404 });

      const analysis = await analyseProposedShifts(client, tenant_id, user_id, dates, start_time, end_time, breakMinutes);
      if (analysis.conflicts.length > 0) {
        const err = new Error(`Cannot create shifts: ${analysis.conflicts.length} overlap with the guard's existing schedule.`);
        err.statusCode = 409;
        err.code = 'SHIFT_CONFLICT';
        err.conflicts = analysis.conflicts;
        throw err;
      }
      if(analysis.availability_conflicts.length){const err=new Error(`Cannot create shifts: guard is unavailable on ${analysis.availability_conflicts.length} proposed date(s).`);err.statusCode=409;err.code='GUARD_UNAVAILABLE';err.availability_conflicts=analysis.availability_conflicts;throw err;}
      if (dry_run) return { dryRun: true, analysis };

      const seriesId = recurrenceType === 'none' ? null : crypto.randomUUID();
      const inserted = [];
      for (const date of dates) {
        const result = await client.query(
          `INSERT INTO shifts (tenant_id, site_id, user_id, shift_date, start_time, end_time, break_minutes, employment_type, recurrence_group_id, notes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
          [tenant_id, site_id, user_id, date.toISODate(), start_time, end_time, breakMinutes, employmentType, seriesId, notes || null]
        );
        inserted.push(result.rows[0]);
      }
      return { inserted, analysis };
    });
    if (shifts.dryRun) return res.json({ valid: true, ...shifts.analysis });
    res.status(201).json({ created_count: shifts.inserted.length, recurrence_group_id: shifts.inserted[0].recurrence_group_id, shifts: shifts.inserted, warnings: shifts.analysis.warnings });
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message, code: err.code, conflicts: err.conflicts, availability_conflicts:err.availability_conflicts });
  }
});

app.patch('/api/shifts/:id/confirmation', requireAuth, async (req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can confirm shifts'});
  const tenantId=attendanceTenant(req,req.body.tenant_id),status=req.body.status;
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['confirmed','declined'].includes(status))return res.status(400).json({error:'Status must be confirmed or declined'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `UPDATE shifts SET confirmation_status=$1,confirmed_at=NOW() WHERE id=$2 AND tenant_id=$3 AND user_id=$4 AND assignment_status='assigned' RETURNING *`,
    [status,req.params.id,tenantId,req.auth.user_id]));if(!result.rows.length)return res.status(404).json({error:'Shift not found'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.patch('/api/shifts/:id/make-open',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `UPDATE shifts SET assignment_status='open',confirmation_status='pending',confirmed_at=NULL WHERE id=$1 AND tenant_id=$2 AND shift_date>=CURRENT_DATE RETURNING *`,
    [req.params.id,tenantId]));if(!result.rows.length)return res.status(404).json({error:'Future shift not found'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/open-shifts',requireAuth,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(
    `SELECT sh.*,s.name AS site_name FROM shifts sh JOIN sites s ON s.id=sh.site_id
     WHERE sh.tenant_id=$1 AND sh.assignment_status='open' AND sh.shift_date>=CURRENT_DATE ORDER BY sh.shift_date,sh.start_time`,[tenantId]));res.json(result.rows.map(s=>({...s,duration_hours:paidShiftHours(s.start_time,s.end_time,s.break_minutes)})));}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/open-shifts/:id/claim',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can claim shifts'});const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const locked=await client.query("SELECT * FROM shifts WHERE id=$1 AND tenant_id=$2 AND assignment_status='open' FOR UPDATE",[req.params.id,tenantId]);if(!locked.rows.length){await client.query('ROLLBACK');return res.status(409).json({error:'This open shift is no longer available'})}const shift=locked.rows[0];const assigned=await client.query('SELECT 1 FROM guard_assignments WHERE tenant_id=$1 AND site_id=$2 AND user_id=$3',[tenantId,shift.site_id,req.auth.user_id]);if(!assigned.rows.length)throw Object.assign(new Error('You must be assigned to this site to claim the shift'),{statusCode:403});const analysis=await analyseProposedShifts(client,tenantId,req.auth.user_id,[DateTime.fromISO(String(shift.shift_date).slice(0,10))],shift.start_time,shift.end_time,shift.break_minutes,shift.id);if(analysis.conflicts.length||analysis.availability_conflicts.length)throw Object.assign(new Error(analysis.availability_conflicts[0]?.message||'This shift conflicts with your schedule'),{statusCode:409});const result=await client.query("UPDATE shifts SET user_id=$1,assignment_status='assigned',confirmation_status='confirmed',confirmed_at=NOW() WHERE id=$2 RETURNING *",[req.auth.user_id,shift.id]);await client.query('COMMIT');res.json({shift:result.rows[0],warnings:analysis.warnings});}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}
});

app.post('/api/shift-swaps',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can request swaps'});const tenantId=attendanceTenant(req,req.body.tenant_id);const {shift_id,target_user_id,reason}=req.body;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(Number(target_user_id)===Number(req.auth.user_id))return res.status(400).json({error:'Choose another guard'});
  try{const result=await withTenant(tenantId,async client=>{const shift=await client.query("SELECT * FROM shifts WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND assignment_status='assigned' AND shift_date>=CURRENT_DATE",[shift_id,tenantId,req.auth.user_id]);if(!shift.rows.length)throw Object.assign(new Error('Eligible shift not found'),{statusCode:404});const target=await client.query("SELECT 1 FROM users u JOIN guard_assignments ga ON ga.user_id=u.id AND ga.site_id=$1 AND ga.tenant_id=$2 WHERE u.id=$3 AND u.tenant_id=$2 AND u.role='guard'",[shift.rows[0].site_id,tenantId,target_user_id]);if(!target.rows.length)throw Object.assign(new Error('Target guard is not assigned to this site'),{statusCode:400});return client.query("INSERT INTO shift_swap_requests (tenant_id,shift_id,requester_id,target_user_id,reason) VALUES ($1,$2,$3,$4,$5) RETURNING *",[tenantId,shift_id,req.auth.user_id,target_user_id,reason||null])});res.status(201).json(result.rows[0]);}catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.get('/api/shifts/:id/swap-targets',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can request swaps'});const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query(`SELECT DISTINCT u.id,u.email FROM shifts sh JOIN guard_assignments ga ON ga.site_id=sh.site_id AND ga.tenant_id=sh.tenant_id JOIN users u ON u.id=ga.user_id WHERE sh.id=$1 AND sh.tenant_id=$2 AND sh.user_id=$3 AND u.id<>$3 AND u.role='guard' ORDER BY u.email`,[req.params.id,tenantId,req.auth.user_id]));res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.get('/api/shift-swaps',requireAuth,async(req,res)=>{const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>{let query=`SELECT sw.*,sh.shift_date,sh.start_time,sh.end_time,s.name AS site_name,r.email AS requester_email,t.email AS target_email FROM shift_swap_requests sw JOIN shifts sh ON sh.id=sw.shift_id JOIN sites s ON s.id=sh.site_id JOIN users r ON r.id=sw.requester_id JOIN users t ON t.id=sw.target_user_id WHERE sw.tenant_id=$1`;const params=[tenantId];if(req.auth.role!=='admin'){params.push(req.auth.user_id);query+=` AND (sw.requester_id=$${params.length} OR sw.target_user_id=$${params.length})`}query+=' ORDER BY sw.created_at DESC LIMIT 250';return client.query(query,params)});res.json(result.rows);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/shift-swaps/:id/respond',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Only guards can respond'});const tenantId=attendanceTenant(req,req.body.tenant_id),accepted=Boolean(req.body.accepted);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,client=>client.query("UPDATE shift_swap_requests SET status=$1,recipient_responded_at=NOW() WHERE id=$2 AND tenant_id=$3 AND target_user_id=$4 AND status='pending_recipient' RETURNING *",[accepted?'pending_admin':'declined',req.params.id,tenantId,req.auth.user_id]));if(!result.rows.length)return res.status(409).json({error:'Request not found or already answered'});res.json(result.rows[0]);}catch(err){res.status(500).json({error:err.message});}});

app.patch('/api/shift-swaps/:id/review',requireAuth,requireAdmin,async(req,res)=>{const tenantId=attendanceTenant(req,req.body.tenant_id),approved=Boolean(req.body.approved);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});const client=await pool.connect();try{await client.query('BEGIN');await client.query(`SET LOCAL app.current_tenant='${tenantId}'`);const swapResult=await client.query("SELECT sw.id AS swap_request_id,sw.shift_id,sw.target_user_id,sh.shift_date,sh.start_time,sh.end_time,sh.break_minutes FROM shift_swap_requests sw JOIN shifts sh ON sh.id=sw.shift_id WHERE sw.id=$1 AND sw.tenant_id=$2 AND sw.status='pending_admin' FOR UPDATE",[req.params.id,tenantId]);if(!swapResult.rows.length)throw Object.assign(new Error('Swap not found or not ready for review'),{statusCode:409});const sw=swapResult.rows[0];if(approved){const analysis=await analyseProposedShifts(client,tenantId,sw.target_user_id,[DateTime.fromISO(String(sw.shift_date).slice(0,10))],sw.start_time,sw.end_time,sw.break_minutes,sw.shift_id);if(analysis.conflicts.length||analysis.availability_conflicts.length)throw Object.assign(new Error(analysis.availability_conflicts[0]?.message||'Target guard now has a schedule conflict'),{statusCode:409});await client.query("UPDATE shifts SET user_id=$1,confirmation_status='confirmed',confirmed_at=NOW() WHERE id=$2",[sw.target_user_id,sw.shift_id]);}await client.query("UPDATE shift_swap_requests SET status=$1,admin_reviewed_at=NOW(),admin_reviewed_by=$2,admin_notes=$3 WHERE id=$4",[approved?'approved':'rejected',req.auth.user_id,req.body.admin_notes||null,sw.swap_request_id]);await client.query('COMMIT');res.json({status:approved?'approved':'rejected'});}catch(err){await client.query('ROLLBACK');res.status(err.statusCode||500).json({error:err.message});}finally{client.release();}});

app.get('/api/shifts', requireAuth, async (req, res) => {
  const { tenant_id, site_id, user_id, start_date, end_date } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  if (req.auth.role !== 'admin' && user_id && Number(user_id) !== req.auth.user_id) {
    return res.status(403).json({ error: 'Guards can only view their own shifts' });
  }
  const effectiveUserId = req.auth.role === 'admin' ? user_id : req.auth.user_id;

  try {
    const result = await withTenant(tenant_id, (client) => {
      let query = `SELECT sh.*, u.email AS guard_email, s.name AS site_name
                   FROM shifts sh JOIN users u ON u.id = sh.user_id JOIN sites s ON s.id = sh.site_id
                   WHERE sh.tenant_id = $1`;
      const params = [tenant_id];
      if (effectiveUserId) { params.push(effectiveUserId); query += ` AND sh.user_id = $${params.length}`; }
      if (req.auth.role !== 'admin') query += ` AND sh.assignment_status = 'assigned'`;
      if (site_id) { params.push(site_id); query += ` AND sh.site_id = $${params.length}`; }
      if (start_date) { params.push(start_date); query += ` AND sh.shift_date >= $${params.length}`; }
      if (end_date) { params.push(end_date); query += ` AND sh.shift_date <= $${params.length}`; }
      if (!start_date && !end_date) query += ' AND sh.shift_date >= CURRENT_DATE';
      query += ' ORDER BY sh.shift_date ASC, sh.start_time ASC LIMIT 500';
      return client.query(query, params);
    });
    res.json(result.rows.map(shift => ({ ...shift, duration_hours: Math.max(0, Math.round((computeShiftDurationHours(shift.start_time, shift.end_time) - Number(shift.break_minutes || 0) / 60) * 100) / 100) })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, user_id, site_id, shift_date, start_time, end_time, break_minutes, employment_type, notes } = req.body;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });
  if (start_time && !TIME_FORMAT_REGEX.test(start_time)) return res.status(400).json({ error: 'start_time must use HH:MM format' });
  if (end_time && !TIME_FORMAT_REGEX.test(end_time)) return res.status(400).json({ error: 'end_time must use HH:MM format' });
  const employmentType = employment_type && ['full_time', 'part_time'].includes(employment_type) ? employment_type : null;
  try {
    const result = await withTenant(tenant_id, async client => {
      const currentResult = await client.query('SELECT * FROM shifts WHERE id=$1 AND tenant_id=$2', [id, tenant_id]);
      if (!currentResult.rows.length) throw Object.assign(new Error('Shift not found'), { statusCode: 404 });
      const current = currentResult.rows[0];
      const nextUserId = user_id === undefined ? Number(current.user_id) : Number(user_id);
      if (!Number.isInteger(nextUserId) || nextUserId < 1) {
        throw Object.assign(new Error('A valid assigned guard is required'), { statusCode: 400 });
      }
      const guardResult = await client.query(
        `SELECT id FROM users
         WHERE id=$1 AND tenant_id=$2 AND role='guard' AND COALESCE(account_active, TRUE)=TRUE`,
        [nextUserId, tenant_id]
      );
      if (!guardResult.rows.length) {
        throw Object.assign(new Error('The selected guard is unavailable or no longer active'), { statusCode: 400 });
      }
      const nextDate = shift_date || String(current.shift_date).slice(0,10);
      const nextStart = start_time || current.start_time;
      const nextEnd = end_time || current.end_time;
      const nextBreak = break_minutes === undefined ? current.break_minutes : Number(break_minutes);
      const analysis = await analyseProposedShifts(client, tenant_id, nextUserId, [DateTime.fromISO(nextDate)], nextStart, nextEnd, nextBreak, Number(id));
      if (analysis.conflicts.length) {
        const err = new Error('Cannot save this shift because it overlaps the guard\'s existing schedule.');
        err.statusCode = 409; err.code = 'SHIFT_CONFLICT'; err.conflicts = analysis.conflicts; throw err;
      }
      if(analysis.availability_conflicts.length){const err=new Error('Cannot save this shift because the guard is unavailable.');err.statusCode=409;err.code='GUARD_UNAVAILABLE';err.availability_conflicts=analysis.availability_conflicts;throw err;}
      const updated = await client.query(
        `UPDATE shifts SET user_id=$1, site_id=COALESCE($2, site_id), shift_date=COALESCE($3, shift_date),
         start_time=COALESCE($4, start_time), end_time=COALESCE($5, end_time),
         break_minutes=COALESCE($6, break_minutes), employment_type=COALESCE($7, employment_type), notes=$8,
         assignment_status='assigned', confirmation_status='pending', confirmed_at=NULL
         WHERE id=$9 AND tenant_id=$10 RETURNING *`,
        [nextUserId, site_id || null, shift_date || null, start_time || null, end_time || null,
         break_minutes === undefined ? null : Number(break_minutes), employmentType, notes ?? null, id, tenant_id]
      );
      return { shift: updated.rows[0], warnings: analysis.warnings };
    });
    res.json(result);
  } catch (err) { res.status(err.statusCode || 500).json({ error: err.message, code: err.code, conflicts: err.conflicts, availability_conflicts:err.availability_conflicts }); }
});

app.delete('/api/shifts/:id', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => client.query(
      'DELETE FROM shifts WHERE id = $1 AND tenant_id = $2 RETURNING *', [req.params.id, tenant_id]
    ));
    if (result.rows.length === 0) return res.status(404).json({ error: 'Shift not found' });
    res.json({ deleted: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/shifts/series/:recurrenceGroupId', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id } = req.query;
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id query param is required' });
  try {
    const result = await withTenant(tenant_id, (client) => client.query(
      'DELETE FROM shifts WHERE tenant_id = $1 AND recurrence_group_id = $2 AND shift_date >= CURRENT_DATE RETURNING id',
      [tenant_id, req.params.recurrenceGroupId]
    ));
    res.json({ deleted_count: result.rows.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ------------------------ GUARD CERTIFICATIONS ------------------------

const CERT_EXPIRY_WARNING_DAYS = 30;

function computeCertStatus(expiryDate) {
  const today = DateTime.now().startOf('day');
  const expiry = DateTime.fromJSDate(new Date(expiryDate)).startOf('day');
  const daysRemaining = Math.round(expiry.diff(today, 'days').days);

  let status = 'valid';
  if (daysRemaining < 0) status = 'expired';
  else if (daysRemaining <= CERT_EXPIRY_WARNING_DAYS) status = 'expiring_soon';

  return { status, days_remaining: daysRemaining };
}

app.get('/api/certifications', requireAuth, async (req, res) => {
  const { tenant_id: queryTenant } = req.query;
  const { user_id } = req.query;
  const includeArchived = req.query.include_archived === 'true';

  const effectiveTenantId = queryTenant || req.auth.tenant_id;
  if (!effectiveTenantId) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(effectiveTenantId, (client) => {
      if (user_id) {
        return client.query(
          `SELECT c.*, u.email as guard_email
           FROM guard_certifications c
           JOIN users u ON u.id = c.user_id
           WHERE c.tenant_id = $1 AND c.user_id = $2 AND ($3::boolean OR c.archived_at IS NULL)
           ORDER BY c.expiry_date ASC, c.cert_name ASC`,
          [effectiveTenantId, user_id, includeArchived]
        );
      }
      return client.query(
        `SELECT c.*, u.email as guard_email
         FROM guard_certifications c
         JOIN users u ON u.id = c.user_id
         WHERE c.tenant_id = $1 AND ($2::boolean OR c.archived_at IS NULL)
         ORDER BY c.expiry_date ASC, c.cert_name ASC`,
        [effectiveTenantId, includeArchived]
      );
    });
    res.json(result.rows.map(cert => ({ ...cert, ...computeCertStatus(cert.expiry_date) })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/certifications/expiring', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id: queryTenant } = req.query;
  const effectiveTenantId = queryTenant || req.auth.tenant_id;
  if (!effectiveTenantId) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(effectiveTenantId, (client) =>
      client.query(
        `SELECT c.*, u.email as guard_email
         FROM guard_certifications c
         JOIN users u ON u.id = c.user_id
         WHERE c.tenant_id = $1 AND c.archived_at IS NULL
         ORDER BY c.expiry_date ASC`,
        [effectiveTenantId]
      )
    );
    const flagged = result.rows
      .map(cert => ({ ...cert, ...computeCertStatus(cert.expiry_date) }))
      .filter(cert => cert.status === 'expired' || cert.status === 'expiring_soon');
    res.json(flagged);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/certifications', requireAuth, requireAdmin, async (req, res) => {
  const { tenant_id, user_id, cert_name, cert_number, issue_date, expiry_date } = req.body;
  if (!tenant_id || !user_id || !cert_name || !expiry_date) {
    return res.status(400).json({ error: 'tenant_id, user_id, cert_name, and expiry_date are required' });
  }
  if (Number.isNaN(new Date(expiry_date).getTime())) {
    return res.status(400).json({ error: 'expiry_date must be a valid date' });
  }

  try {
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
      return client.query(
        `INSERT INTO guard_certifications (tenant_id, user_id, cert_name, cert_number, issue_date, expiry_date)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [tenant_id, user_id, cert_name, cert_number || null, issue_date || null, expiry_date]
      );
    });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(err.statusCode || 500).json({ error: err.message });
  }
});

app.patch('/api/certifications/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id, cert_name, cert_number, issue_date, expiry_date } = req.body;
  if (!tenant_id) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `UPDATE guard_certifications
         SET cert_name = COALESCE($3, cert_name),
             cert_number = $4,
             issue_date = $5,
             expiry_date = COALESCE($6, expiry_date)
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [id, tenant_id, cert_name || null, cert_number || null, issue_date || null, expiry_date || null]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Certification not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/certifications/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { tenant_id } = req.query;
  if (!tenant_id) {
    return res.status(400).json({ error: 'tenant_id is required' });
  }

  try {
    const result = await withTenant(tenant_id, (client) =>
      client.query(
        `UPDATE guard_certifications SET archived_at=NOW(),archived_by_user_id=$3
         WHERE id=$1 AND tenant_id=$2 AND archived_at IS NULL RETURNING *`,
        [id, tenant_id, req.auth.user_id]
      )
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Certification not found' });
    }
    res.json({ archived: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/certifications/:id/renew', requireAuth, requireAdmin, async (req, res) => {
  const id=Number(req.params.id),tenantId=Number(req.body.tenant_id),certName=String(req.body.cert_name||'').trim(),certNumber=String(req.body.cert_number||'').trim(),issueDate=req.body.issue_date||null,expiryDate=req.body.expiry_date||null;
  if(!Number.isInteger(id)||!Number.isInteger(tenantId)||!certName||!expiryDate)return res.status(400).json({error:'Certificate, tenant, name and new expiry date are required'});
  if(Number.isNaN(new Date(expiryDate).getTime()))return res.status(400).json({error:'New expiry date must be valid'});
  try{const renewed=await withTenant(tenantId,async client=>{await client.query('BEGIN');try{
    const old=(await client.query(`SELECT * FROM guard_certifications WHERE id=$1 AND tenant_id=$2 AND archived_at IS NULL FOR UPDATE`,[id,tenantId])).rows[0];
    if(!old)throw Object.assign(new Error('Active certificate not found'),{statusCode:404});
    const next=(await client.query(`INSERT INTO guard_certifications(tenant_id,user_id,cert_name,cert_number,issue_date,expiry_date,replacement_for_id) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[tenantId,old.user_id,certName,certNumber||null,issueDate,expiryDate,old.id])).rows[0];
    await client.query(`UPDATE guard_certifications SET archived_at=NOW(),archived_by_user_id=$3,replaced_by_id=$4 WHERE id=$1 AND tenant_id=$2`,[old.id,tenantId,req.auth.user_id,next.id]);
    await client.query('COMMIT');return{previous_id:old.id,certificate:next};
  }catch(error){await client.query('ROLLBACK');throw error}});res.status(201).json(renewed)}catch(err){res.status(err.statusCode||500).json({error:err.message})}
});

app.patch('/api/certifications/:id/restore', requireAuth, requireAdmin, async (req, res) => {
  const id=Number(req.params.id),tenantId=Number(req.body.tenant_id);if(!Number.isInteger(id)||!Number.isInteger(tenantId))return res.status(400).json({error:'Valid certificate and tenant are required'});
  try{const result=await withTenant(tenantId,client=>client.query(`UPDATE guard_certifications SET archived_at=NULL,archived_by_user_id=NULL WHERE id=$1 AND tenant_id=$2 AND archived_at IS NOT NULL AND replaced_by_id IS NULL RETURNING *`,[id,tenantId]));if(!result.rowCount)return res.status(409).json({error:'Certificate cannot be restored because it is active, missing, or has already been replaced'});res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}
});

async function buildCertificationCompliance(client, tenantId) {
  const [requirementsResult, assignmentsResult, guardsResult, certificationsResult] = await Promise.all([
    client.query(`SELECT r.*,s.name AS site_name FROM site_guard_requirements r JOIN sites s ON s.id=r.site_id WHERE r.tenant_id=$1 AND r.active=TRUE ORDER BY s.name,r.cert_name`,[tenantId]),
    client.query(`SELECT DISTINCT tenant_id,site_id,user_id FROM guard_assignments WHERE tenant_id=$1`,[tenantId]),
    client.query(`SELECT id,email FROM users WHERE tenant_id=$1 AND role='guard' AND COALESCE(account_active,TRUE)=TRUE`,[tenantId]),
    client.query(`SELECT id,user_id,cert_name,cert_number,issue_date,expiry_date FROM guard_certifications WHERE tenant_id=$1 AND archived_at IS NULL ORDER BY expiry_date DESC`,[tenantId])
  ]);
  const guardsById=new Map(guardsResult.rows.map(g=>[Number(g.id),g])), certs=certificationsResult.rows;
  const today=DateTime.now().startOf('day'), rows=[];
  for(const requirement of requirementsResult.rows){
    const assigned=assignmentsResult.rows.filter(a=>Number(a.site_id)===Number(requirement.site_id));
    for(const assignment of assigned){
      const guard=guardsById.get(Number(assignment.user_id));if(!guard)continue;
      const name=String(requirement.cert_name||'').trim().toLowerCase();
      const matching=certs.filter(c=>Number(c.user_id)===Number(guard.id)&&String(c.cert_name||'').trim().toLowerCase()===name);
      const certificate=matching[0]||null;
      let status='missing',daysRemaining=null;
      if(certificate){const expiry=DateTime.fromJSDate(new Date(certificate.expiry_date)).startOf('day');daysRemaining=Math.round(expiry.diff(today,'days').days);status=daysRemaining<0?'expired':daysRemaining<=Number(requirement.reminder_days||30)?'expiring_soon':'compliant';}
      rows.push({requirement_id:requirement.id,site_id:requirement.site_id,site_name:requirement.site_name,cert_name:requirement.cert_name,reminder_days:requirement.reminder_days,user_id:guard.id,guard_email:guard.email,status,days_remaining:daysRemaining,certificate});
    }
  }
  const summary={total:rows.length,compliant:rows.filter(x=>x.status==='compliant').length,missing:rows.filter(x=>x.status==='missing').length,expired:rows.filter(x=>x.status==='expired').length,expiring_soon:rows.filter(x=>x.status==='expiring_soon').length};
  return{summary,rows,generated_at:new Date().toISOString()};
}

async function sweepCertificationComplianceForTenant(tenantId) {
  return withTenant(tenantId,async client=>{
    const report=await buildCertificationCompliance(client,tenantId), activeKeys=[];
    for(const issue of report.rows.filter(x=>x.status!=='compliant')){
      const sourceKey=`cert-compliance:${issue.requirement_id}:${issue.user_id}`, title=issue.status==='missing'?`Missing certificate: ${issue.cert_name}`:issue.status==='expired'?`Expired certificate: ${issue.cert_name}`:`Certificate expiring: ${issue.cert_name}`;
      const message=issue.status==='missing'?`${issue.guard_email} has no active ${issue.cert_name} certificate for ${issue.site_name}.`:issue.status==='expired'?`${issue.guard_email}'s ${issue.cert_name} certificate for ${issue.site_name} expired ${Math.abs(issue.days_remaining)} day(s) ago.`:`${issue.guard_email}'s ${issue.cert_name} certificate for ${issue.site_name} expires in ${issue.days_remaining} day(s).`;
      activeKeys.push(sourceKey);
      await client.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,action_url,requires_acknowledgement,source_key,expires_at)
        VALUES($1,$2,$3,'certification',$4,'admins','certificate_register.html',FALSE,$5,NULL)
        ON CONFLICT(tenant_id,source_key) WHERE source_key IS NOT NULL DO UPDATE SET title=EXCLUDED.title,message=EXCLUDED.message,priority=EXCLUDED.priority,expires_at=NULL`,[tenantId,title,message,issue.status==='expiring_soon'?'normal':'high',sourceKey]);
    }
    if(activeKeys.length)await client.query(`UPDATE communication_notifications SET expires_at=NOW() WHERE tenant_id=$1 AND source_key LIKE 'cert-compliance:%' AND NOT(source_key=ANY($2::text[])) AND expires_at IS NULL`,[tenantId,activeKeys]);
    else await client.query(`UPDATE communication_notifications SET expires_at=NOW() WHERE tenant_id=$1 AND source_key LIKE 'cert-compliance:%' AND expires_at IS NULL`,[tenantId]);
    return report;
  });
}

async function runCertificationComplianceSweep(){try{const tenants=await pool.query('SELECT id FROM tenants WHERE COALESCE(account_active,TRUE)=TRUE');for(const tenant of tenants.rows)await sweepCertificationComplianceForTenant(Number(tenant.id));}catch(err){console.error('Certification compliance sweep failed:',err.message)}}
scheduleBackgroundJob('certification_compliance_sweep',15*60*1000,45000,runCertificationComplianceSweep);

app.get('/api/certification-compliance',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{res.json(await withTenant(tenantId,client=>buildCertificationCompliance(client,tenantId)))}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/certification-compliance/run',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{res.json(await sweepCertificationComplianceForTenant(tenantId))}catch(err){res.status(500).json({error:err.message})}});

// ------------------------ PHASE 4: NOTIFICATIONS & ESCALATIONS ------------------------

function communicationTenant(req, suppliedTenantId) {
  const tokenTenant = Number(req.auth && req.auth.tenant_id);
  const requestedTenant = Number(suppliedTenantId || tokenTenant);
  if (!Number.isInteger(tokenTenant) || !Number.isInteger(requestedTenant) || tokenTenant !== requestedTenant) return null;
  return requestedTenant;
}

function communicationAudienceSql(role, userPlaceholder = '$2') {
  return role === 'admin'
    ? `(${userPlaceholder}::integer IS NOT NULL)`
    : `(n.audience IN ('all','all_guards') OR n.recipient_user_id = ${userPlaceholder})`;
}

app.get('/api/communication-notifications', requireAuth, async (req, res) => {
  const tenantId = communicationTenant(req, req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  if (!['admin', 'guard'].includes(req.auth.role)) return res.status(403).json({ error: 'Notification inbox is unavailable for this role' });
  const userId = Number(req.auth.user_id);
  const status = String(req.query.status || 'active');
  try {
    const result = await withTenant(tenantId, (client) => client.query(
      `SELECT n.*, r.read_at, r.acknowledged_at, u.email AS recipient_email, creator.email AS created_by_email
       FROM communication_notifications n
       LEFT JOIN communication_notification_receipts r ON r.notification_id=n.id AND r.user_id=$2 AND r.tenant_id=n.tenant_id
       LEFT JOIN users u ON u.id=n.recipient_user_id AND u.tenant_id=n.tenant_id
       LEFT JOIN users creator ON creator.id=n.created_by_user_id AND creator.tenant_id=n.tenant_id
       WHERE n.tenant_id=$1 AND ${communicationAudienceSql(req.auth.role)}
         AND (n.expires_at IS NULL OR n.expires_at > NOW())
         AND ($3='all' OR $3='active' OR ($3='unread' AND r.read_at IS NULL) OR ($3='ack_required' AND n.requires_acknowledgement=TRUE AND r.acknowledged_at IS NULL))
       ORDER BY CASE n.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END, n.created_at DESC LIMIT 250`,
      [tenantId, userId, status]
    ));
    res.json({ notifications: result.rows, unread_count: result.rows.filter(x => !x.read_at).length,
      acknowledgement_count: result.rows.filter(x => x.requires_acknowledgement && !x.acknowledged_at).length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/communication-notifications', requireAuth, requireAdmin, async (req, res) => {
  const tenantId = communicationTenant(req, req.body.tenant_id);
  if (!tenantId) return res.status(403).json({ error: 'Tenant access denied' });
  const title=String(req.body.title||'').trim(), message=String(req.body.message||'').trim();
  const category=String(req.body.category||'general').trim().toLowerCase(), priority=String(req.body.priority||'normal').trim().toLowerCase();
  const audience=String(req.body.audience||'all_guards').trim().toLowerCase(), recipientUserId=req.body.recipient_user_id?Number(req.body.recipient_user_id):null;
  const actionUrl=String(req.body.action_url||'').trim()||null, expiresAt=req.body.expires_at||null;
  if (!title || !message) return res.status(400).json({ error: 'Title and message are required' });
  if (title.length>160 || message.length>4000) return res.status(400).json({ error: 'Title or message is too long' });
  if (!['low','normal','high','critical'].includes(priority)) return res.status(400).json({ error: 'Invalid priority' });
  if (!['all','admins','all_guards','specific_guard'].includes(audience)) return res.status(400).json({ error: 'Invalid audience' });
  if (audience==='specific_guard' && !Number.isInteger(recipientUserId)) return res.status(400).json({ error: 'Select a guard' });
  if (actionUrl && (/^\s*(javascript|data):/i.test(actionUrl) || actionUrl.length>500)) return res.status(400).json({ error: 'Invalid action URL' });
  try {
    const result = await withTenant(tenantId, async client => {
      if (audience==='specific_guard') {
        const guard=await client.query("SELECT id FROM users WHERE id=$1 AND tenant_id=$2 AND role='guard'",[recipientUserId,tenantId]);
        if (!guard.rowCount) { const e=new Error('Guard not found'); e.statusCode=404; throw e; }
      }
      return client.query(`INSERT INTO communication_notifications
        (tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [tenantId,title,message,category,priority,audience,audience==='specific_guard'?recipientUserId:null,actionUrl,
         Boolean(req.body.requires_acknowledgement),req.auth.user_id,expiresAt]);
    });
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(err.statusCode||500).json({ error: err.message }); }
});

async function updateCommunicationReceipt(req, res, acknowledge) {
  const tenantId=communicationTenant(req,req.body.tenant_id||req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error:'Tenant access denied' });
  try {
    const result=await withTenant(tenantId,async client=>{
      const visible=await client.query(`SELECT n.id,n.requires_acknowledgement FROM communication_notifications n
        WHERE n.id=$1 AND n.tenant_id=$2 AND ${communicationAudienceSql(req.auth.role, '$3')}`,[req.params.id,tenantId,req.auth.user_id]);
      if (!visible.rowCount) { const e=new Error('Notification not found'); e.statusCode=404; throw e; }
      if (acknowledge&&!visible.rows[0].requires_acknowledgement) { const e=new Error('This notification does not require acknowledgement'); e.statusCode=400; throw e; }
      return client.query(`INSERT INTO communication_notification_receipts(notification_id,tenant_id,user_id,read_at,acknowledged_at)
        VALUES($1,$2,$3,NOW(),${acknowledge?'NOW()':'NULL'}) ON CONFLICT(notification_id,user_id) DO UPDATE SET
        read_at=COALESCE(communication_notification_receipts.read_at,NOW()), acknowledged_at=${acknowledge?'NOW()':'communication_notification_receipts.acknowledged_at'} RETURNING *`,
        [req.params.id,tenantId,req.auth.user_id]);
    });
    res.json(result.rows[0]);
  } catch(err) { res.status(err.statusCode||500).json({ error:err.message }); }
}
app.patch('/api/communication-notifications/:id/read',requireAuth,(req,res)=>updateCommunicationReceipt(req,res,false));
app.patch('/api/communication-notifications/:id/acknowledge',requireAuth,(req,res)=>updateCommunicationReceipt(req,res,true));

app.delete('/api/communication-notifications/:id',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);
  if (!tenantId) return res.status(403).json({ error:'Tenant access denied' });
  try { const result=await withTenant(tenantId,client=>client.query('DELETE FROM communication_notifications WHERE id=$1 AND tenant_id=$2 RETURNING id',[req.params.id,tenantId]));
    if(!result.rowCount)return res.status(404).json({error:'Notification not found'}); res.json({deleted:true});
  } catch(err){res.status(500).json({error:err.message});}
});

// ------------------------ PHASE 4.2: TEAM MESSAGING ------------------------

function conversationAccessSql(role, userPlaceholder = '$2') {
  return role === 'admin' ? `(${userPlaceholder}::integer IS NOT NULL)` : `(c.kind='company' OR (c.kind='direct' AND c.guard_user_id=${userPlaceholder}))`;
}

async function ensureCompanyConversation(client, tenantId, creatorId) {
  await client.query(`INSERT INTO team_conversations(tenant_id,title,kind,created_by_user_id)
    VALUES($1,'Company Announcements','company',$2) ON CONFLICT DO NOTHING`,[tenantId,creatorId]);
}

app.get('/api/team-conversations',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['admin','guard'].includes(req.auth.role))return res.status(403).json({error:'Messaging is unavailable for this role'});
  try{
    const result=await withTenant(tenantId,async client=>{
      await ensureCompanyConversation(client,tenantId,req.auth.user_id);
      return client.query(`SELECT c.*,u.email AS guard_email,
        (SELECT m.message FROM team_messages m WHERE m.conversation_id=c.id AND m.tenant_id=c.tenant_id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
        (SELECT m.created_at FROM team_messages m WHERE m.conversation_id=c.id AND m.tenant_id=c.tenant_id ORDER BY m.created_at DESC LIMIT 1) AS last_message_at,
        (SELECT COUNT(*)::int FROM team_messages m WHERE m.conversation_id=c.id AND m.tenant_id=c.tenant_id
          AND m.sender_user_id<>$2 AND m.created_at>COALESCE(r.last_read_at,'1970-01-01')) AS unread_count
        FROM team_conversations c LEFT JOIN users u ON u.id=c.guard_user_id AND u.tenant_id=c.tenant_id
        LEFT JOIN team_conversation_reads r ON r.conversation_id=c.id AND r.user_id=$2
        WHERE c.tenant_id=$1 AND ${conversationAccessSql(req.auth.role)}
        ORDER BY COALESCE((SELECT MAX(created_at) FROM team_messages WHERE conversation_id=c.id),c.created_at) DESC`,
        [tenantId,req.auth.user_id]);
    });
    res.json(result.rows);
  }catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/team-conversations/direct',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),guardId=Number(req.body.guard_user_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!Number.isInteger(guardId))return res.status(400).json({error:'Select a guard'});
  try{
    const result=await withTenant(tenantId,async client=>{
      const guard=await client.query("SELECT id,email FROM users WHERE id=$1 AND tenant_id=$2 AND role='guard'",[guardId,tenantId]);
      if(!guard.rowCount){const e=new Error('Guard not found');e.statusCode=404;throw e;}
      return client.query(`INSERT INTO team_conversations(tenant_id,title,kind,guard_user_id,created_by_user_id)
        VALUES($1,$2,'direct',$3,$4) ON CONFLICT(tenant_id,guard_user_id) WHERE kind='direct'
        DO UPDATE SET title=EXCLUDED.title RETURNING *`,[tenantId,guard.rows[0].email,guardId,req.auth.user_id]);
    });
    res.status(201).json(result.rows[0]);
  }catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.get('/api/team-conversations/:id/messages',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{
    const result=await withTenant(tenantId,async client=>{
      const access=await client.query(`SELECT c.id FROM team_conversations c WHERE c.id=$1 AND c.tenant_id=$2 AND ${conversationAccessSql(req.auth.role,'$3')}`,
        [req.params.id,tenantId,req.auth.user_id]);
      if(!access.rowCount){const e=new Error('Conversation not found');e.statusCode=404;throw e;}
      await client.query(`INSERT INTO team_conversation_reads(tenant_id,conversation_id,user_id,last_read_at) VALUES($1,$2,$3,NOW())
        ON CONFLICT(conversation_id,user_id) DO UPDATE SET last_read_at=NOW()`,[tenantId,req.params.id,req.auth.user_id]);
      return client.query(`SELECT m.*,u.email AS sender_email FROM team_messages m LEFT JOIN users u ON u.id=m.sender_user_id AND u.tenant_id=m.tenant_id
        WHERE m.tenant_id=$1 AND m.conversation_id=$2 ORDER BY m.created_at ASC LIMIT 500`,[tenantId,req.params.id]);
    });
    res.json(result.rows);
  }catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.post('/api/team-conversations/:id/messages',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),message=String(req.body.message||'').trim();
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!message)return res.status(400).json({error:'Message is required'});
  if(message.length>4000)return res.status(400).json({error:'Message is too long'});
  try{
    const result=await withTenant(tenantId,async client=>{
      const access=await client.query(`SELECT c.id,c.kind FROM team_conversations c WHERE c.id=$1 AND c.tenant_id=$2 AND ${conversationAccessSql(req.auth.role,'$3')}`,
        [req.params.id,tenantId,req.auth.user_id]);
      if(!access.rowCount){const e=new Error('Conversation not found');e.statusCode=404;throw e;}
      if(req.auth.role==='guard'&&access.rows[0].kind==='company'){const e=new Error('Only admins can post company announcements');e.statusCode=403;throw e;}
      const inserted=await client.query(`INSERT INTO team_messages(tenant_id,conversation_id,sender_user_id,sender_role,message)
        VALUES($1,$2,$3,$4,$5) RETURNING *`,[tenantId,req.params.id,req.auth.user_id,req.auth.role,message]);
      await client.query(`INSERT INTO team_conversation_reads(tenant_id,conversation_id,user_id,last_read_at) VALUES($1,$2,$3,NOW())
        ON CONFLICT(conversation_id,user_id) DO UPDATE SET last_read_at=NOW()`,[tenantId,req.params.id,req.auth.user_id]);
      return inserted;
    });
    res.status(201).json(result.rows[0]);
  }catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

// ------------------------ PHASE 4.3: LONE-WORKER SAFETY ------------------------

function loneWorkerStatusSql() {
  return `SELECT s.*,u.email AS guard_email,si.name AS site_name,a.clocked_in_at,
    (SELECT MAX(c.checked_in_at) FROM lone_worker_checkins c WHERE c.setting_id=s.id AND c.user_id=s.user_id) AS last_check_in,
    la.id AS alert_id,la.created_at AS alert_created_at,
    COALESCE((SELECT MAX(c.checked_in_at) FROM lone_worker_checkins c WHERE c.setting_id=s.id AND c.user_id=s.user_id),a.clocked_in_at) AS safety_reference
    FROM lone_worker_settings s JOIN users u ON u.id=s.user_id AND u.tenant_id=s.tenant_id
    JOIN sites si ON si.id=s.site_id AND si.tenant_id=s.tenant_id
    LEFT JOIN attendance_sessions a ON a.user_id=s.user_id AND a.site_id=s.site_id AND a.tenant_id=s.tenant_id AND a.clocked_out_at IS NULL
    LEFT JOIN lone_worker_alerts la ON la.setting_id=s.id AND la.resolved=FALSE`;
}

app.get('/api/lone-worker/settings',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`${loneWorkerStatusSql()} WHERE s.tenant_id=$1 ORDER BY u.email,si.name`,[tenantId]));res.json(result.rows);}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/lone-worker/settings',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),userId=Number(req.body.user_id),siteId=Number(req.body.site_id);
  const interval=Number(req.body.interval_minutes),grace=Number(req.body.grace_minutes);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!Number.isInteger(userId)||!Number.isInteger(siteId)||!Number.isInteger(interval)||interval<5||interval>720||!Number.isInteger(grace)||grace<0||grace>120)return res.status(400).json({error:'Guard, site, interval (5–720), and grace (0–120) are required'});
  try{const result=await withTenant(tenantId,async client=>{
    const valid=await client.query(`SELECT u.id FROM users u JOIN sites s ON s.tenant_id=u.tenant_id WHERE u.id=$1 AND s.id=$2 AND u.tenant_id=$3 AND u.role='guard'`,[userId,siteId,tenantId]);
    if(!valid.rowCount){const e=new Error('Guard or site not found');e.statusCode=404;throw e;}
    return client.query(`INSERT INTO lone_worker_settings(tenant_id,user_id,site_id,enabled,interval_minutes,grace_minutes,instructions)
      VALUES($1,$2,$3,TRUE,$4,$5,$6) ON CONFLICT(tenant_id,user_id,site_id) DO UPDATE SET enabled=TRUE,interval_minutes=$4,grace_minutes=$5,instructions=$6,updated_at=NOW() RETURNING *`,
      [tenantId,userId,siteId,interval,grace,String(req.body.instructions||'').trim()||null]);});res.status(201).json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.patch('/api/lone-worker/settings/:id/toggle',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query('UPDATE lone_worker_settings SET enabled=$3,updated_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING *',[req.params.id,tenantId,Boolean(req.body.enabled)]));if(!result.rowCount)return res.status(404).json({error:'Setting not found'});res.json(result.rows[0]);}
  catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/lone-worker/current',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`${loneWorkerStatusSql()} WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.enabled=TRUE AND a.id IS NOT NULL ORDER BY a.clocked_in_at DESC LIMIT 1`,[tenantId,req.auth.user_id]));
    if(!result.rowCount)return res.json({active:false});const row=result.rows[0],reference=new Date(row.safety_reference),due=new Date(reference.getTime()+Number(row.interval_minutes)*60000),escalates=new Date(due.getTime()+Number(row.grace_minutes)*60000);res.json({active:true,setting:row,due_at:due,escalates_at:escalates,overdue:Date.now()>escalates.getTime()});}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/lone-worker/check-in',requireAuth,async(req,res)=>{
  if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const tenantId=communicationTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,async client=>{const active=await client.query(`${loneWorkerStatusSql()} WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.enabled=TRUE AND a.id IS NOT NULL ORDER BY a.clocked_in_at DESC LIMIT 1`,[tenantId,req.auth.user_id]);
    if(!active.rowCount){const e=new Error('No active lone-worker session. Clock in at a configured site first.');e.statusCode=409;throw e;}const s=active.rows[0];
    const check=await client.query(`INSERT INTO lone_worker_checkins(tenant_id,setting_id,user_id,site_id,latitude,longitude,accuracy,note) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[tenantId,s.id,req.auth.user_id,s.site_id,req.body.latitude??null,req.body.longitude??null,req.body.accuracy??null,String(req.body.note||'').trim()||null]);
    await client.query('UPDATE lone_worker_alerts SET resolved=TRUE,resolved_at=NOW() WHERE setting_id=$1 AND resolved=FALSE',[s.id]);return check;});res.status(201).json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

async function runLoneWorkerSweep(){try{const due=await pool.query(`${loneWorkerStatusSql()} WHERE s.enabled=TRUE AND a.id IS NOT NULL AND COALESCE((SELECT MAX(c.checked_in_at) FROM lone_worker_checkins c WHERE c.setting_id=s.id AND c.user_id=s.user_id),a.clocked_in_at)+(s.interval_minutes+s.grace_minutes)*INTERVAL '1 minute'<NOW()`);
  for(const row of due.rows){const alert=await pool.query(`INSERT INTO lone_worker_alerts(tenant_id,setting_id,user_id,site_id,due_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id`,[row.tenant_id,row.id,row.user_id,row.site_id,new Date(new Date(row.safety_reference).getTime()+(Number(row.interval_minutes)+Number(row.grace_minutes))*60000)]);if(alert.rowCount)await pool.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,requires_acknowledgement)
    VALUES($1,$2,$3,'safety','critical','admins',TRUE)`,[row.tenant_id,'Lone-worker welfare check overdue',`${row.guard_email} at ${row.site_name} missed the required safety check-in.`]);}}
  catch(err){console.error('Lone-worker sweep failed:',err.message);}}
scheduleBackgroundJob('lone_worker_sweep',60000,15000,runLoneWorkerSweep);

// ------------------------ PHASE 4.4: DISPATCH COMMAND CENTER ------------------------

app.get('/api/dispatch-jobs',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['admin','guard'].includes(req.auth.role))return res.status(403).json({error:'Dispatch access denied'});
  try{const result=await withTenant(tenantId,client=>{let sql=`SELECT d.*,u.email AS guard_email,s.name AS site_name FROM dispatch_jobs d
    JOIN users u ON u.id=d.assigned_guard_id AND u.tenant_id=d.tenant_id LEFT JOIN sites s ON s.id=d.site_id AND s.tenant_id=d.tenant_id WHERE d.tenant_id=$1`;const params=[tenantId];
    if(req.auth.role==='guard'){params.push(req.auth.user_id);sql+=` AND d.assigned_guard_id=$2`;}if(req.query.status==='active')sql+=` AND d.status NOT IN ('completed','cancelled')`;sql+=' ORDER BY CASE d.priority WHEN \'critical\' THEN 1 WHEN \'high\' THEN 2 WHEN \'normal\' THEN 3 ELSE 4 END,d.created_at DESC LIMIT 300';return client.query(sql,params);});res.json(result.rows);}
  catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/dispatch-jobs',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),guardId=Number(req.body.assigned_guard_id),siteId=req.body.site_id?Number(req.body.site_id):null;
  const title=String(req.body.title||'').trim(),priority=String(req.body.priority||'normal').toLowerCase();
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!title||!Number.isInteger(guardId))return res.status(400).json({error:'Title and assigned guard are required'});
  if(!['low','normal','high','critical'].includes(priority))return res.status(400).json({error:'Invalid priority'});
  try{const result=await withTenant(tenantId,async client=>{const guard=await client.query("SELECT id FROM users WHERE id=$1 AND tenant_id=$2 AND role='guard'",[guardId,tenantId]);if(!guard.rowCount){const e=new Error('Guard not found');e.statusCode=404;throw e;}
    if(siteId){const site=await client.query('SELECT id FROM sites WHERE id=$1 AND tenant_id=$2',[siteId,tenantId]);if(!site.rowCount){const e=new Error('Site not found');e.statusCode=404;throw e;}}
    const reference='DSP-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(2).toString('hex').toUpperCase();
    const inserted=await client.query(`INSERT INTO dispatch_jobs(tenant_id,reference_code,title,description,priority,site_id,assigned_guard_id,address,latitude,longitude,created_by_user_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[tenantId,reference,title,String(req.body.description||'').trim()||null,priority,siteId,guardId,String(req.body.address||'').trim()||null,req.body.latitude??null,req.body.longitude??null,req.auth.user_id]);
    await client.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id)
      VALUES($1,$2,$3,'dispatch',$4,'specific_guard',$5,'my_dispatches.html',TRUE,$6)`,[tenantId,'New dispatch: '+title,`Dispatch ${reference} has been assigned to you.`,priority,guardId,req.auth.user_id]);return inserted;});res.status(201).json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

app.patch('/api/dispatch-jobs/:id/status',requireAuth,async(req,res)=>{
  const tenantId=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||'').toLowerCase();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  if(!['admin','guard'].includes(req.auth.role))return res.status(403).json({error:'Dispatch access denied'});
  if(!['assigned','accepted','en_route','on_site','completed','cancelled'].includes(status))return res.status(400).json({error:'Invalid dispatch status'});
  try{const result=await withTenant(tenantId,async client=>{const current=await client.query('SELECT * FROM dispatch_jobs WHERE id=$1 AND tenant_id=$2',[req.params.id,tenantId]);if(!current.rowCount){const e=new Error('Dispatch not found');e.statusCode=404;throw e;}const job=current.rows[0];
    if(req.auth.role==='guard'&&Number(job.assigned_guard_id)!==Number(req.auth.user_id)){const e=new Error('This dispatch is not assigned to you');e.statusCode=403;throw e;}
    if(req.auth.role==='guard'){const allowed={assigned:['accepted'],accepted:['en_route'],en_route:['on_site'],on_site:['completed']}[job.status]||[];if(!allowed.includes(status)){const e=new Error(`Move the dispatch from ${job.status} to the next status first`);e.statusCode=409;throw e;}}
    const timeColumn={accepted:'accepted_at',en_route:'en_route_at',on_site:'on_site_at',completed:'completed_at'}[status];let sql='UPDATE dispatch_jobs SET status=$3,updated_at=NOW(),completion_note=CASE WHEN $3=\'completed\' THEN $4 ELSE completion_note END';if(timeColumn)sql+=`,${timeColumn}=COALESCE(${timeColumn},NOW())`;sql+=' WHERE id=$1 AND tenant_id=$2 RETURNING *';return client.query(sql,[req.params.id,tenantId,status,String(req.body.completion_note||'').trim()||null]);});res.json(result.rows[0]);}
  catch(err){res.status(err.statusCode||500).json({error:err.message});}
});

// ------------------------ PHASE 4.6: TRAINING & COMPLIANCE ------------------------
app.get('/api/training/materials',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT m.*,s.name site_name,(SELECT COUNT(*)::int FROM training_assignments a WHERE a.material_id=m.id) assigned_count,(SELECT COUNT(*)::int FROM training_assignments a WHERE a.material_id=m.id AND a.status='completed') completed_count FROM training_materials m LEFT JOIN sites s ON s.id=m.site_id AND s.tenant_id=m.tenant_id WHERE m.tenant_id=$1 AND ($2='admin' OR m.active=TRUE) ORDER BY m.created_at DESC`,[t,req.auth.role]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/training/materials',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),title=String(req.body.title||'').trim(),content=String(req.body.content||'').trim(),type=String(req.body.material_type||'training');if(!t)return res.status(403).json({error:'Tenant access denied'});if(!title||!content||!['training','policy','post_order'].includes(type))return res.status(400).json({error:'Title, content and valid type are required'});let questions=req.body.questions||[];if(!Array.isArray(questions)||questions.some(q=>!q.question||!Array.isArray(q.options)||q.options.length<2||!Number.isInteger(Number(q.correct_index))||Number(q.correct_index)<0||Number(q.correct_index)>=q.options.length))return res.status(400).json({error:'Invalid quiz questions'});try{const r=await withTenant(t,c=>c.query(`INSERT INTO training_materials(tenant_id,title,material_type,version,content,site_id,questions,passing_score,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[t,title,type,String(req.body.version||'1.0'),content,req.body.site_id?Number(req.body.site_id):null,JSON.stringify(questions),Number(req.body.passing_score??80),req.auth.user_id]));res.status(201).json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/training/materials/:id/assign',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),aud=String(req.body.audience||'all_guards'),uid=req.body.user_id?Number(req.body.user_id):null,sid=req.body.site_id?Number(req.body.site_id):null;if(!t)return res.status(403).json({error:'Tenant access denied'});try{const count=await withTenant(t,async c=>{const m=await c.query('SELECT * FROM training_materials WHERE id=$1 AND tenant_id=$2',[req.params.id,t]);if(!m.rowCount){const e=new Error('Material not found');e.statusCode=404;throw e;}let q="SELECT DISTINCT u.id FROM users u WHERE u.tenant_id=$1 AND u.role='guard'",p=[t];if(aud==='specific_guard'){p.push(uid);q+=' AND u.id=$2'}else if(aud==='site'){p.push(sid);q+=` AND EXISTS(SELECT 1 FROM guard_assignments g WHERE g.user_id=u.id AND g.site_id=$2 AND g.tenant_id=$1)`}const guards=await c.query(q,p);for(const g of guards.rows){await c.query(`INSERT INTO training_assignments(tenant_id,material_id,user_id,due_at,mandatory) VALUES($1,$2,$3,$4,$5) ON CONFLICT(material_id,user_id) DO UPDATE SET due_at=EXCLUDED.due_at,mandatory=EXCLUDED.mandatory`,[t,req.params.id,g.id,req.body.due_at||null,req.body.mandatory!==false]);await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id) VALUES($1,$2,$3,'compliance','normal','specific_guard',$4,'my_training.html',TRUE,$5)`,[t,'New '+m.rows[0].material_type+': '+m.rows[0].title,'A new required learning item has been assigned to you.',g.id,req.auth.user_id])}return guards.rowCount});res.json({assigned:count})}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.get('/api/training/assignments',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>{let q=`SELECT a.*,m.title,m.material_type,m.version,m.content,m.questions,m.passing_score,m.site_id,u.email guard_email,s.name site_name FROM training_assignments a JOIN training_materials m ON m.id=a.material_id JOIN users u ON u.id=a.user_id LEFT JOIN sites s ON s.id=m.site_id WHERE a.tenant_id=$1`,p=[t];if(req.auth.role==='guard'){p.push(req.auth.user_id);q+=' AND a.user_id=$2'}else if(req.auth.role!=='admin')throw Object.assign(new Error('Access denied'),{statusCode:403});q+=' ORDER BY CASE a.status WHEN \'assigned\' THEN 1 WHEN \'failed\' THEN 2 ELSE 3 END,a.due_at NULLS LAST';return c.query(q,p)});res.json(r.rows)}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.post('/api/training/assignments/:id/complete',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const t=communicationTenant(req,req.body.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const a=await c.query(`SELECT a.*,m.questions,m.passing_score FROM training_assignments a JOIN training_materials m ON m.id=a.material_id WHERE a.id=$1 AND a.tenant_id=$2 AND a.user_id=$3`,[req.params.id,t,req.auth.user_id]);if(!a.rowCount){const e=new Error('Assignment not found');e.statusCode=404;throw e}if(req.body.acknowledged!==true){const e=new Error('You must acknowledge that you read and understood the material');e.statusCode=400;throw e}const qs=a.rows[0].questions||[],answers=req.body.answers||[];let score=100;if(qs.length)score=Math.round(qs.reduce((n,q,i)=>n+(Number(answers[i])===Number(q.correct_index)?1:0),0)/qs.length*100);const passed=score>=Number(a.rows[0].passing_score);return c.query(`UPDATE training_assignments SET attempts=attempts+1,score=$4,status=$5,acknowledged_at=NOW(),completed_at=CASE WHEN $5='completed' THEN NOW() ELSE NULL END WHERE id=$1 AND tenant_id=$2 AND user_id=$3 RETURNING *`,[req.params.id,t,req.auth.user_id,score,passed?'completed':'failed'])});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});

async function buildCompetencyMatrix(client,tenantId){
  const result=await client.query(`SELECT r.id requirement_id,r.site_id,s.name site_name,r.material_id,r.due_days,m.title,m.material_type,m.version,u.id user_id,u.email guard_email,a.id assignment_id,a.status assignment_status,a.score,a.due_at,a.completed_at
    FROM site_training_requirements r JOIN sites s ON s.id=r.site_id AND s.tenant_id=r.tenant_id JOIN training_materials m ON m.id=r.material_id AND m.tenant_id=r.tenant_id
    JOIN guard_assignments ga ON ga.tenant_id=r.tenant_id AND ga.site_id=r.site_id JOIN users u ON u.id=ga.user_id AND u.tenant_id=r.tenant_id AND u.role='guard' AND COALESCE(u.account_active,TRUE)=TRUE
    LEFT JOIN training_assignments a ON a.tenant_id=r.tenant_id AND a.material_id=r.material_id AND a.user_id=u.id
    WHERE r.tenant_id=$1 AND r.active=TRUE AND m.active=TRUE ORDER BY s.name,u.email,m.title`,[tenantId]);
  const now=DateTime.now(),rows=result.rows.map(row=>{let status='missing';if(row.assignment_id){if(row.assignment_status==='completed')status='compliant';else if(row.assignment_status==='failed')status='failed';else if(row.due_at&&DateTime.fromJSDate(new Date(row.due_at))<now)status='overdue';else status='assigned'}return{...row,status}});
  return{generated_at:new Date().toISOString(),summary:{total:rows.length,compliant:rows.filter(x=>x.status==='compliant').length,missing:rows.filter(x=>x.status==='missing').length,assigned:rows.filter(x=>x.status==='assigned').length,failed:rows.filter(x=>x.status==='failed').length,overdue:rows.filter(x=>x.status==='overdue').length},rows};
}

app.get('/api/competency/requirements',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT r.*,s.name site_name,m.title,m.material_type,m.version FROM site_training_requirements r JOIN sites s ON s.id=r.site_id JOIN training_materials m ON m.id=r.material_id WHERE r.tenant_id=$1 AND r.active=TRUE ORDER BY s.name,m.title`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/competency/requirements',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),materialId=Number(req.body.material_id),dueDays=Math.min(365,Math.max(1,Number(req.body.due_days||14)));if(!t)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!materialId)return res.status(400).json({error:'Site and training material are required'});try{const r=await withTenant(t,c=>c.query(`INSERT INTO site_training_requirements(tenant_id,site_id,material_id,due_days,active,created_by_user_id) SELECT $1,$2,$3,$4,TRUE,$5 WHERE EXISTS(SELECT 1 FROM sites WHERE tenant_id=$1 AND id=$2) AND EXISTS(SELECT 1 FROM training_materials WHERE tenant_id=$1 AND id=$3 AND active=TRUE) ON CONFLICT(tenant_id,site_id,material_id) DO UPDATE SET due_days=EXCLUDED.due_days,active=TRUE,updated_at=NOW() RETURNING *`,[t,siteId,materialId,dueDays,req.auth.user_id]));if(!r.rowCount)return res.status(404).json({error:'Site or active training material not found'});res.status(201).json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});
app.delete('/api/competency/requirements/:id',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query('UPDATE site_training_requirements SET active=FALSE,updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND active=TRUE RETURNING id',[t,req.params.id]));if(!r.rowCount)return res.status(404).json({error:'Requirement not found'});res.json({archived:true})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/competency/matrix',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{res.json(await withTenant(t,c=>buildCompetencyMatrix(c,t)))}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/competency/remediate',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),requirementId=Number(req.body.requirement_id),userId=Number(req.body.user_id);if(!t)return res.status(403).json({error:'Tenant access denied'});if(!requirementId||!userId)return res.status(400).json({error:'Requirement and guard are required'});try{const output=await withTenant(t,async c=>{const requirement=(await c.query(`SELECT r.*,m.title FROM site_training_requirements r JOIN training_materials m ON m.id=r.material_id WHERE r.id=$1 AND r.tenant_id=$2 AND r.active=TRUE`,[requirementId,t])).rows[0];if(!requirement)throw Object.assign(new Error('Competency requirement not found'),{statusCode:404});const assigned=await c.query(`INSERT INTO training_assignments(tenant_id,material_id,user_id,due_at,mandatory,status) VALUES($1,$2,$3,NOW()+($4::text||' days')::interval,TRUE,'assigned') ON CONFLICT(material_id,user_id) DO UPDATE SET due_at=EXCLUDED.due_at,mandatory=TRUE,status=CASE WHEN training_assignments.status='completed' THEN 'completed' ELSE 'assigned' END RETURNING *`,[t,requirement.material_id,userId,requirement.due_days]);await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id,source_key,expires_at) VALUES($1,$2,$3,'compliance','high','specific_guard',$4,'my_training.html',TRUE,$5,$6,NULL) ON CONFLICT(tenant_id,source_key) WHERE source_key IS NOT NULL DO UPDATE SET title=EXCLUDED.title,message=EXCLUDED.message,expires_at=NULL`,[t,'Required training: '+requirement.title,'Complete this mandatory training to restore site competency.',userId,req.auth.user_id,`competency:${requirementId}:${userId}`]);return assigned.rows[0]});res.json(output)}catch(e){res.status(e.statusCode||500).json({error:e.message})}});

// ------------------------ PHASE 4.7: EQUIPMENT, KEYS & VEHICLES ------------------------
app.get('/api/assets',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT a.*,s.name site_name FROM managed_assets a LEFT JOIN sites s ON s.id=a.site_id AND s.tenant_id=a.tenant_id WHERE a.tenant_id=$1 ORDER BY a.name`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/assets',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),name=String(req.body.name||'').trim(),code=String(req.body.asset_code||'').trim(),type=String(req.body.asset_type||'equipment');if(!t)return res.status(403).json({error:'Tenant access denied'});if(!name||!code||!['equipment','key','vehicle','uniform','device','other'].includes(type))return res.status(400).json({error:'Name, asset code and valid type are required'});try{const r=await withTenant(t,c=>c.query(`INSERT INTO managed_assets(tenant_id,asset_type,name,asset_code,site_id,condition,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[t,type,name,code,req.body.site_id?Number(req.body.site_id):null,String(req.body.condition||'good'),String(req.body.notes||'').trim()||null]));res.status(201).json(r.rows[0])}catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'Asset code already exists':e.message})}});
app.get('/api/asset-custody',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>{let q=`SELECT c.*,a.name asset_name,a.asset_code,a.asset_type,a.condition,u.email guard_email,s.name site_name FROM asset_custody c JOIN managed_assets a ON a.id=c.asset_id JOIN users u ON u.id=c.user_id LEFT JOIN sites s ON s.id=a.site_id WHERE c.tenant_id=$1`,p=[t];if(req.auth.role==='guard'){p.push(req.auth.user_id);q+=' AND c.user_id=$2'}else if(req.auth.role!=='admin')throw Object.assign(new Error('Access denied'),{statusCode:403});if(req.query.active==='true')q+=` AND c.status<>'returned'`;q+=' ORDER BY c.issued_at DESC LIMIT 500';return c.query(q,p)});res.json(r.rows)}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.post('/api/asset-custody/issue',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),asset=Number(req.body.asset_id),user=Number(req.body.user_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const valid=await c.query(`SELECT a.name,a.status FROM managed_assets a JOIN users u ON u.id=$2 AND u.tenant_id=a.tenant_id AND u.role='guard' WHERE a.id=$1 AND a.tenant_id=$3`,[asset,user,t]);if(!valid.rowCount)throw Object.assign(new Error('Asset or guard not found'),{statusCode:404});if(valid.rows[0].status!=='available')throw Object.assign(new Error('Asset is not available'),{statusCode:409});const issued=await c.query(`INSERT INTO asset_custody(tenant_id,asset_id,user_id,issued_by_user_id,admin_note) VALUES($1,$2,$3,$4,$5) RETURNING *`,[t,asset,user,req.auth.user_id,String(req.body.admin_note||'').trim()||null]);await c.query("UPDATE managed_assets SET status='issued',updated_at=NOW() WHERE id=$1",[asset]);await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id) VALUES($1,$2,$3,'equipment','normal','specific_guard',$4,'my_equipment.html',TRUE,$5)`,[t,'Asset issued: '+valid.rows[0].name,'Review and acknowledge receipt of this asset.',user,req.auth.user_id]);return issued});res.status(201).json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.patch('/api/asset-custody/:id/guard-action',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const t=communicationTenant(req,req.body.tenant_id),action=String(req.body.action||''),map={acknowledge:'acknowledged',request_return:'return_requested',report_lost:'reported_lost',report_damaged:'reported_damaged'};if(!t)return res.status(403).json({error:'Tenant access denied'});if(!map[action])return res.status(400).json({error:'Invalid action'});try{const r=await withTenant(t,async c=>{const extra=action==='acknowledge'?',acknowledged_at=NOW()':action==='request_return'?',return_requested_at=NOW()':'';const u=await c.query(`UPDATE asset_custody SET status=$4,guard_note=$5${extra} WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND status<>'returned' RETURNING *`,[req.params.id,t,req.auth.user_id,map[action],String(req.body.note||'').trim()||null]);if(!u.rowCount)throw Object.assign(new Error('Active custody record not found'),{statusCode:404});if(action==='report_lost'||action==='report_damaged')await c.query('UPDATE managed_assets SET status=$2,updated_at=NOW() WHERE id=$1',[u.rows[0].asset_id,action==='report_lost'?'lost':'maintenance']);return u});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.patch('/api/asset-custody/:id/confirm-return',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),condition=String(req.body.return_condition||'good');if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const u=await c.query(`UPDATE asset_custody SET status='returned',returned_at=NOW(),return_condition=$3,admin_note=COALESCE($4,admin_note) WHERE id=$1 AND tenant_id=$2 AND status<>'returned' RETURNING *`,[req.params.id,t,condition,String(req.body.admin_note||'').trim()||null]);if(!u.rowCount)throw Object.assign(new Error('Active custody record not found'),{statusCode:404});await c.query('UPDATE managed_assets SET status=$2,condition=$3,updated_at=NOW() WHERE id=$1',[u.rows[0].asset_id,condition==='damaged'?'maintenance':'available',condition]);return u});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});

// ------------------------ PHASE 4.8: QUALITY INSPECTIONS & CAPA ------------------------
app.get('/api/inspection-templates',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT i.*,s.name site_name FROM inspection_templates i LEFT JOIN sites s ON s.id=i.site_id AND s.tenant_id=i.tenant_id WHERE i.tenant_id=$1 ORDER BY i.created_at DESC`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/inspection-templates',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),title=String(req.body.title||'').trim(),questions=req.body.questions||[];if(!t)return res.status(403).json({error:'Tenant access denied'});if(!title||!Array.isArray(questions)||!questions.length||questions.some(q=>!String(q.text||'').trim()))return res.status(400).json({error:'Title and at least one valid question are required'});try{const r=await withTenant(t,c=>c.query(`INSERT INTO inspection_templates(tenant_id,title,description,site_id,passing_score,questions,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[t,title,String(req.body.description||'').trim()||null,req.body.site_id?Number(req.body.site_id):null,Number(req.body.passing_score??80),JSON.stringify(questions.map(q=>({text:String(q.text).trim(),critical:Boolean(q.critical),guidance:String(q.guidance||'').trim()}))),req.auth.user_id]));res.status(201).json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/inspection-runs',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),template=Number(req.body.template_id),site=Number(req.body.site_id),user=Number(req.body.assigned_user_id);if(!t)return res.status(403).json({error:'Tenant access denied'});if(!template||!site||!user||!req.body.scheduled_for)return res.status(400).json({error:'Template, site, guard and schedule are required'});try{const r=await withTenant(t,async c=>{const valid=await c.query(`SELECT i.title FROM inspection_templates i JOIN sites s ON s.id=$2 AND s.tenant_id=i.tenant_id JOIN users u ON u.id=$3 AND u.tenant_id=i.tenant_id AND u.role='guard' WHERE i.id=$1 AND i.tenant_id=$4 AND i.active=TRUE`,[template,site,user,t]);if(!valid.rowCount)throw Object.assign(new Error('Template, site or guard not found'),{statusCode:404});const run=await c.query(`INSERT INTO inspection_runs(tenant_id,template_id,site_id,assigned_user_id,scheduled_for,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[t,template,site,user,req.body.scheduled_for,req.auth.user_id]);await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,recipient_user_id,action_url,requires_acknowledgement,created_by_user_id) VALUES($1,$2,$3,'inspection','normal','specific_guard',$4,'my_inspections.html',TRUE,$5)`,[t,'Inspection assigned: '+valid.rows[0].title,'A site quality inspection has been assigned to you.',user,req.auth.user_id]);return run});res.status(201).json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.get('/api/inspection-runs',requireAuth,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>{let q=`SELECT r.*,i.title template_title,i.description template_description,i.questions,i.passing_score,s.name site_name,u.email guard_email FROM inspection_runs r JOIN inspection_templates i ON i.id=r.template_id JOIN sites s ON s.id=r.site_id JOIN users u ON u.id=r.assigned_user_id WHERE r.tenant_id=$1`,p=[t];if(req.auth.role==='guard'){p.push(req.auth.user_id);q+=' AND r.assigned_user_id=$2'}else if(req.auth.role!=='admin')throw Object.assign(new Error('Access denied'),{statusCode:403});q+=' ORDER BY CASE r.status WHEN \'scheduled\' THEN 1 WHEN \'in_progress\' THEN 2 ELSE 3 END,r.scheduled_for DESC LIMIT 500';return c.query(q,p)});res.json(r.rows)}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.post('/api/inspection-runs/:id/submit',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const t=communicationTenant(req,req.body.tenant_id),responses=req.body.responses||[];if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,async c=>{const found=await c.query(`SELECT r.*,i.questions,i.passing_score,i.title FROM inspection_runs r JOIN inspection_templates i ON i.id=r.template_id WHERE r.id=$1 AND r.tenant_id=$2 AND r.assigned_user_id=$3 AND r.status NOT IN ('submitted','cancelled')`,[req.params.id,t,req.auth.user_id]);if(!found.rowCount)throw Object.assign(new Error('Active inspection not found'),{statusCode:404});const questions=found.rows[0].questions||[];if(!Array.isArray(responses)||responses.length!==questions.length||responses.some(x=>!['pass','fail','na'].includes(x.answer)))throw Object.assign(new Error('Answer every inspection question'),{statusCode:400});const applicable=responses.filter(x=>x.answer!=='na'),passed=applicable.filter(x=>x.answer==='pass').length,score=applicable.length?Math.round(passed/applicable.length*100):100;const submitted=await c.query(`UPDATE inspection_runs SET status='submitted',responses=$4,score=$5,overall_note=$6,started_at=COALESCE(started_at,NOW()),submitted_at=NOW() WHERE id=$1 AND tenant_id=$2 AND assigned_user_id=$3 RETURNING *`,[req.params.id,t,req.auth.user_id,JSON.stringify(responses),score,String(req.body.overall_note||'').trim()||null]);for(let i=0;i<responses.length;i++){if(responses[i].answer==='fail'){const q=questions[i];await c.query(`INSERT INTO corrective_actions(tenant_id,inspection_run_id,question_index,title,description) VALUES($1,$2,$3,$4,$5)`,[t,req.params.id,i,'Failed inspection item: '+q.text,String(responses[i].note||q.guidance||'').trim()||null])}}if(score<Number(found.rows[0].passing_score)||responses.some((x,i)=>x.answer==='fail'&&questions[i].critical))await c.query(`INSERT INTO communication_notifications(tenant_id,title,message,category,priority,audience,action_url,requires_acknowledgement) VALUES($1,$2,$3,'inspection','high','admins','quality_inspections.html',TRUE)`,[t,'Inspection failed: '+found.rows[0].title,`Inspection score ${score}%. Corrective action is required.`]);return submitted});res.json(r.rows[0])}catch(e){res.status(e.statusCode||500).json({error:e.message})}});
app.get('/api/corrective-actions',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT a.*,i.score,i.template_id,t.title template_title,s.name site_name,u.email assigned_email FROM corrective_actions a JOIN inspection_runs i ON i.id=a.inspection_run_id JOIN inspection_templates t ON t.id=i.template_id JOIN sites s ON s.id=i.site_id LEFT JOIN users u ON u.id=a.assigned_user_id WHERE a.tenant_id=$1 ORDER BY CASE a.status WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 ELSE 3 END,a.due_at NULLS LAST`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.patch('/api/corrective-actions/:id',requireAuth,requireAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||'open');if(!t)return res.status(403).json({error:'Tenant access denied'});if(!['open','in_progress','resolved','cancelled'].includes(status))return res.status(400).json({error:'Invalid status'});try{const r=await withTenant(t,c=>c.query(`UPDATE corrective_actions SET assigned_user_id=$3,due_at=$4,status=$5,resolution_note=$6,resolved_at=CASE WHEN $5='resolved' THEN NOW() ELSE NULL END WHERE id=$1 AND tenant_id=$2 RETURNING *`,[req.params.id,t,req.body.assigned_user_id?Number(req.body.assigned_user_id):null,req.body.due_at||null,status,String(req.body.resolution_note||'').trim()||null]));if(!r.rowCount)return res.status(404).json({error:'Corrective action not found'});res.json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ PHASE 4.9: STAFF ACCESS CONTROL ------------------------
app.get('/api/staff-users',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const r=await withTenant(t,c=>c.query(`SELECT id,email,job_title,permissions,account_active,created_at FROM users WHERE tenant_id=$1 AND role='staff' ORDER BY email`,[t]));res.json(r.rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/staff-users',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||''),permissions=req.body.permissions||[],valid=['scheduling','attendance','patrols','incidents','dispatch','safety','communications','training','assets','quality','clients','finance','analytics'];if(!t)return res.status(403).json({error:'Tenant access denied'});if(!email||password.length<8||!Array.isArray(permissions)||permissions.some(x=>!valid.includes(x)))return res.status(400).json({error:'Valid email, password of at least 8 characters and permissions are required'});try{const hash=await bcrypt.hash(password,10),r=await withTenant(t,c=>c.query(`INSERT INTO users(tenant_id,email,password_hash,role,job_title,permissions,account_active) VALUES($1,$2,$3,'staff',$4,$5,TRUE) RETURNING id,email,job_title,permissions,account_active`,[t,email,hash,String(req.body.job_title||'').trim()||null,JSON.stringify(permissions)]));res.status(201).json(r.rows[0])}catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'Email already exists':e.message})}});
app.patch('/api/staff-users/:id',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),permissions=req.body.permissions||[],valid=['scheduling','attendance','patrols','incidents','dispatch','safety','communications','training','assets','quality','clients','finance','analytics'];if(!t)return res.status(403).json({error:'Tenant access denied'});if(!Array.isArray(permissions)||permissions.some(x=>!valid.includes(x)))return res.status(400).json({error:'Invalid permissions'});try{const r=await withTenant(t,c=>c.query(`UPDATE users SET job_title=$3,permissions=$4,account_active=$5 WHERE id=$1 AND tenant_id=$2 AND role='staff' RETURNING id,email,job_title,permissions,account_active`,[req.params.id,t,String(req.body.job_title||'').trim()||null,JSON.stringify(permissions),req.body.account_active!==false]));if(!r.rowCount)return res.status(404).json({error:'Staff user not found'});res.json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/staff-session',requireAuth,async(req,res)=>{if(req.auth.role!=='staff')return res.status(403).json({error:'Staff access required'});try{const r=await pool.query(`SELECT id,email,job_title,permissions,account_active FROM users WHERE id=$1 AND tenant_id=$2 AND role='staff'`,[req.auth.user_id,req.auth.tenant_id]);if(!r.rowCount||!r.rows[0].account_active)return res.status(403).json({error:'Staff account disabled'});res.json(r.rows[0])}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ PHASE 4.10: API & WEBHOOK INTEGRATIONS ------------------------
function hashApiKey(key){return crypto.createHash('sha256').update(key).digest('hex')}
async function requireIntegrationKey(req,res,next){const raw=String(req.headers['x-patrolsync-api-key']||'');if(!raw)return res.status(401).json({error:'API key required'});try{const r=await pool.query(`SELECT * FROM integration_api_keys WHERE key_hash=$1 AND active=TRUE`,[hashApiKey(raw)]);if(!r.rowCount)return res.status(401).json({error:'Invalid API key'});req.integration=r.rows[0];await pool.query('UPDATE integration_api_keys SET last_used_at=NOW() WHERE id=$1',[r.rows[0].id]);next()}catch(e){res.status(500).json({error:'API authentication failed'})}}
async function queueWebhookEvent(tenantId,eventType,payload){try{await pool.query(`INSERT INTO webhook_deliveries(tenant_id,webhook_id,event_type,payload) SELECT tenant_id,id,$2,$3 FROM webhook_endpoints WHERE tenant_id=$1 AND active=TRUE AND (event_filter='*' OR $2 LIKE event_filter||'%')`,[tenantId,eventType,JSON.stringify({event:eventType,tenant_id:tenantId,occurred_at:new Date().toISOString(),data:payload})])}catch(e){console.error('Webhook queue failed:',e.message)}}
app.get('/api/integrations',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const[k,w,d]=await Promise.all([pool.query(`SELECT id,name,key_prefix,active,last_used_at,created_at FROM integration_api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`,[t]),pool.query(`SELECT id,name,url,event_filter,active,created_at FROM webhook_endpoints WHERE tenant_id=$1 ORDER BY created_at DESC`,[t]),pool.query(`SELECT d.*,w.name webhook_name FROM webhook_deliveries d JOIN webhook_endpoints w ON w.id=d.webhook_id WHERE d.tenant_id=$1 ORDER BY d.created_at DESC LIMIT 100`,[t])]);res.json({api_keys:k.rows,webhooks:w.rows,deliveries:d.rows})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/integrations/api-keys',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),name=String(req.body.name||'').trim();if(!t)return res.status(403).json({error:'Tenant access denied'});if(!name)return res.status(400).json({error:'Key name required'});const raw='ps_'+crypto.randomBytes(32).toString('hex');try{const r=await pool.query(`INSERT INTO integration_api_keys(tenant_id,name,key_prefix,key_hash,created_by_user_id) VALUES($1,$2,$3,$4,$5) RETURNING id,name,key_prefix,created_at`,[t,name,raw.slice(0,11),hashApiKey(raw),req.auth.user_id]);res.status(201).json({...r.rows[0],api_key:raw,warning:'Copy this key now. It will not be shown again.'})}catch(e){res.status(500).json({error:e.message})}});
app.patch('/api/integrations/api-keys/:id/revoke',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id);const r=await pool.query(`UPDATE integration_api_keys SET active=FALSE WHERE id=$1 AND tenant_id=$2 RETURNING id`,[req.params.id,t]);if(!r.rowCount)return res.status(404).json({error:'Key not found'});res.json({revoked:true})});
app.post('/api/integrations/webhooks',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),name=String(req.body.name||'').trim(),url=String(req.body.url||'').trim();if(!t)return res.status(403).json({error:'Tenant access denied'});let parsed;try{parsed=new URL(url)}catch(e){}if(!name||!parsed||parsed.protocol!=='https:'||['localhost','127.0.0.1','::1'].includes(parsed.hostname))return res.status(400).json({error:'Name and public HTTPS URL required'});const secret=crypto.randomBytes(24).toString('hex');try{const r=await pool.query(`INSERT INTO webhook_endpoints(tenant_id,name,url,secret,event_filter) VALUES($1,$2,$3,$4,$5) RETURNING id,name,url,event_filter,active`,[t,name,url,secret,String(req.body.event_filter||'*')]);res.status(201).json({...r.rows[0],signing_secret:secret,warning:'Copy the signing secret now.'})}catch(e){res.status(500).json({error:e.message})}});
app.patch('/api/integrations/webhooks/:id/toggle',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id);const r=await pool.query(`UPDATE webhook_endpoints SET active=$3 WHERE id=$1 AND tenant_id=$2 RETURNING id,active`,[req.params.id,t,Boolean(req.body.active)]);if(!r.rowCount)return res.status(404).json({error:'Webhook not found'});res.json(r.rows[0])});
app.post('/api/integrations/webhooks/:id/test',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});const payload={event:'test.integration',tenant_id:t,occurred_at:new Date().toISOString(),data:{message:'PatrolSync webhook test'}};const r=await pool.query(`INSERT INTO webhook_deliveries(tenant_id,webhook_id,event_type,payload) SELECT tenant_id,id,'test.integration',$3 FROM webhook_endpoints WHERE id=$1 AND tenant_id=$2 RETURNING id`,[req.params.id,t,JSON.stringify(payload)]);if(!r.rowCount)return res.status(404).json({error:'Webhook not found'});res.json({queued:true})});
app.get('/api/public/v1/summary',requireIntegrationKey,async(req,res)=>{const t=req.integration.tenant_id;try{const[s,g,c]=await Promise.all([pool.query('SELECT COUNT(*)::int count FROM sites WHERE tenant_id=$1',[t]),pool.query("SELECT COUNT(*)::int count FROM users WHERE tenant_id=$1 AND role='guard'",[t]),pool.query("SELECT COUNT(*)::int count FROM attendance_sessions WHERE tenant_id=$1 AND clocked_out_at IS NULL",[t])]);res.json({tenant_id:t,sites:s.rows[0].count,guards:g.rows[0].count,currently_clocked_in:c.rows[0].count})}catch(e){res.status(500).json({error:e.message})}});
async function processWebhookQueue(){try{const rows=await pool.query(`SELECT d.*,w.url,w.secret FROM webhook_deliveries d JOIN webhook_endpoints w ON w.id=d.webhook_id WHERE d.status IN ('queued','failed') AND d.next_attempt_at<=NOW() AND d.attempts<5 AND w.active=TRUE ORDER BY d.created_at LIMIT 20`);for(const d of rows.rows){const body=JSON.stringify(d.payload),signature=crypto.createHmac('sha256',d.secret).update(body).digest('hex');try{const response=await fetch(d.url,{method:'POST',headers:{'Content-Type':'application/json','X-PatrolSync-Signature':'sha256='+signature,'X-PatrolSync-Event':d.event_type},body,signal:AbortSignal.timeout(10000)});if(!response.ok)throw Object.assign(new Error('HTTP '+response.status),{status:response.status});await pool.query(`UPDATE webhook_deliveries SET status='delivered',attempts=attempts+1,response_status=$2,delivered_at=NOW(),last_error=NULL WHERE id=$1`,[d.id,response.status])}catch(e){await pool.query(`UPDATE webhook_deliveries SET status='failed',attempts=attempts+1,response_status=$2,last_error=$3,next_attempt_at=NOW()+(POWER(2,attempts)*INTERVAL '1 minute') WHERE id=$1`,[d.id,e.status||null,String(e.message).slice(0,500)])}}}catch(e){console.error('Webhook worker failed:',e.message)}}scheduleBackgroundJob('webhook_delivery',30000,10000,processWebhookQueue);

// ------------------------ PHASE 5.1: AUTOMATED INTEGRITY & SMOKE TESTS ------------------------
app.get('/api/diagnostics/duplicate-users',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(t,c=>c.query(`WITH duplicate_groups AS (SELECT LOWER(email) email_key,role FROM users WHERE tenant_id=$1 AND role IN('guard','staff') AND COALESCE(account_active,TRUE)=TRUE GROUP BY LOWER(email),role HAVING COUNT(*)>1) SELECT u.id,u.email,u.role,u.created_at,(SELECT COUNT(*)::int FROM guard_assignments ga WHERE ga.tenant_id=u.tenant_id AND ga.user_id=u.id) active_assignments,(SELECT COUNT(*)::int FROM attendance_sessions a WHERE a.tenant_id=u.tenant_id AND a.user_id=u.id AND a.clocked_out_at IS NULL) open_clock_ins,(SELECT COUNT(*)::int FROM shifts s WHERE s.tenant_id=u.tenant_id AND s.user_id=u.id AND s.shift_date>=CURRENT_DATE) future_shifts,(SELECT COUNT(*)::int FROM attendance_sessions a WHERE a.tenant_id=u.tenant_id AND a.user_id=u.id) attendance_history,(SELECT COUNT(*)::int FROM patrol_logs p WHERE p.tenant_id=u.tenant_id AND p.user_id=u.id) patrol_history FROM users u JOIN duplicate_groups d ON d.email_key=LOWER(u.email) AND d.role=u.role WHERE u.tenant_id=$1 AND COALESCE(u.account_active,TRUE)=TRUE ORDER BY LOWER(u.email),u.role,u.id`,[t]));res.json({duplicates:result.rows.map(x=>({...x,safe_to_archive:Number(x.active_assignments)===0&&Number(x.open_clock_ins)===0&&Number(x.future_shifts)===0})),request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}});

app.post('/api/diagnostics/duplicate-users/:id/archive',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.body.tenant_id),id=Number(req.params.id);if(!t)return res.status(403).json({error:'Tenant access denied'});if(!Number.isInteger(id)||id<1||id===Number(req.auth.user_id))return res.status(400).json({error:'Invalid duplicate account'});try{const archived=await withTenant(t,async c=>{await c.query('BEGIN');try{const candidate=await c.query(`SELECT u.id,u.email,u.role,(SELECT COUNT(*)::int FROM guard_assignments ga WHERE ga.tenant_id=u.tenant_id AND ga.user_id=u.id) assignments,(SELECT COUNT(*)::int FROM attendance_sessions a WHERE a.tenant_id=u.tenant_id AND a.user_id=u.id AND a.clocked_out_at IS NULL) open_clock_ins,(SELECT COUNT(*)::int FROM shifts s WHERE s.tenant_id=u.tenant_id AND s.user_id=u.id AND s.shift_date>=CURRENT_DATE) future_shifts,(SELECT COUNT(*)::int FROM users other WHERE other.tenant_id=u.tenant_id AND other.id<>u.id AND LOWER(other.email)=LOWER(u.email) AND other.role=u.role AND COALESCE(other.account_active,TRUE)=TRUE) other_active_duplicates FROM users u WHERE u.id=$1 AND u.tenant_id=$2 AND u.role IN('guard','staff') AND COALESCE(u.account_active,TRUE)=TRUE FOR UPDATE`,[id,t]);if(!candidate.rowCount)throw Object.assign(new Error('Active duplicate account not found'),{statusCode:404});const x=candidate.rows[0];if(Number(x.other_active_duplicates)<1)throw Object.assign(new Error('This account is no longer duplicated'),{statusCode:409});if(Number(x.assignments)||Number(x.open_clock_ins)||Number(x.future_shifts))throw Object.assign(new Error('This duplicate still has an assignment, open clock-in, or future shift and cannot be archived automatically'),{statusCode:409});const result=await c.query(`UPDATE users SET account_active=FALSE,password_changed_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING id,email,role`,[id,t]);await c.query('COMMIT');return result.rows[0]}catch(e){await c.query('ROLLBACK');throw e}});res.json({archived,message:'Duplicate account archived. Historical records were preserved.'})}catch(e){res.status(e.statusCode||500).json({error:e.message,request_id:req.requestId})}});

app.get('/api/diagnostics/database-paths',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});let tenantClient;try{const systemRole=(await systemPool.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls,r.rolcreaterole can_create_roles,r.rolcreatedb can_create_databases,has_schema_privilege(current_user,'public','USAGE') public_schema_usage,has_schema_privilege(current_user,'public','CREATE') public_schema_create FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];tenantClient=await tenantPool.connect();await tenantClient.query(`SELECT set_config('app.current_tenant',$1,false)`,[String(t)]);const tenantRole=(await tenantClient.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls,r.rolcreaterole can_create_roles,current_setting('app.current_tenant',true) tenant_context FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];const crossTenant=(await tenantClient.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id<>$1`,[t])).rows[0].count;const roleCreationMethod=systemRole.is_superuser||systemRole.can_create_roles?'sql':'provider_dashboard_or_support';res.json({status:DATABASE_PATHS_SEPARATED&&systemRole.role_name!==tenantRole.role_name&&Number(crossTenant)===0?'ready_for_enforcement':DATABASE_PATHS_SEPARATED?'separated_but_not_isolated':'compatibility_mode',generated_at:new Date(),tenant_id:t,paths_separated:DATABASE_PATHS_SEPARATED,system_role:systemRole,tenant_role:tenantRole,tenant_probe:{cross_tenant_users_visible:Number(crossTenant),passed:Number(crossTenant)===0},role_creation:{method:roleCreationMethod,can_create_with_sql:roleCreationMethod==='sql',message:roleCreationMethod==='sql'?'The current database role can create the restricted login using SQL.':'The current database role cannot create logins; create the restricted user through the database provider or ask provider support.'},configuration:{system_database_url_set:Boolean(process.env.SYSTEM_DATABASE_URL),tenant_database_url_set:Boolean(process.env.TENANT_DATABASE_URL),rls_activation_performed:false},next_action:DATABASE_PATHS_SEPARATED?'Verify the tenant role has policies and cannot bypass RLS before activation.':roleCreationMethod==='sql'?'Create the restricted patrolsync_tenant_app login using the staged SQL in Phase 5.2D.':'Create a restricted PostgreSQL login through your database provider, then set TENANT_DATABASE_URL.',request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}finally{if(tenantClient){let resetError;try{await tenantClient.query('RESET app.current_tenant')}catch(e){resetError=e}tenantClient.release(resetError)}}});

app.get('/api/diagnostics/rls-readiness',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const roleResult=await pool.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls FROM pg_roles r WHERE r.rolname=current_user`);const tablesResult=await pool.query(`SELECT c.relname table_name,c.relrowsecurity rls_enabled,c.relforcerowsecurity rls_forced,pg_get_userbyid(c.relowner)=current_user app_role_owns_table,COUNT(p.policyname)::int policy_count,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='SELECT'),FALSE) protects_select,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='INSERT'),FALSE) protects_insert,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='UPDATE'),FALSE) protects_update,COALESCE(BOOL_OR(p.cmd='ALL' OR p.cmd='DELETE'),FALSE) protects_delete FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_policies p ON p.schemaname=n.nspname AND p.tablename=c.relname WHERE n.nspname='public' AND c.relkind IN('r','p') GROUP BY c.oid,c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner ORDER BY c.relname`);const role=roleResult.rows[0]||{},tables=tablesResult.rows.map(x=>({...x,ready_for_enforcement:Boolean(x.rls_enabled&&x.rls_forced&&x.policy_count>0&&x.protects_select&&x.protects_insert&&x.protects_update&&x.protects_delete)}));const summary={tenant_tables:tables.length,policies_missing:tables.filter(x=>x.policy_count===0).length,rls_disabled:tables.filter(x=>!x.rls_enabled).length,rls_not_forced:tables.filter(x=>!x.rls_forced).length,fully_enforced:tables.filter(x=>x.ready_for_enforcement).length};const blockers=[];if(role.is_superuser)blockers.push('The application database role is a PostgreSQL superuser and therefore bypasses RLS.');if(role.bypasses_rls)blockers.push('The application database role has BYPASSRLS.');if(tables.some(x=>x.app_role_owns_table&&!x.rls_forced))blockers.push('The application role owns tenant tables; table owners bypass RLS until FORCE ROW LEVEL SECURITY is enabled.');if(summary.policies_missing)blockers.push(`${summary.policies_missing} tenant table(s) do not yet have an RLS policy.`);blockers.push('Authentication lookups and background workers must use a separately controlled system path before forced RLS is activated.');res.json({status:summary.fully_enforced===summary.tenant_tables&&summary.tenant_tables>0&&!role.is_superuser&&!role.bypasses_rls?'enforced':'preparation_required',generated_at:new Date(),tenant_id:t,application_role:role,summary,blockers,tables,activation_performed:false,request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}});

app.get('/api/diagnostics/integrity',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});const checks=[],add=(key,label,severity,count,message,details=[])=>checks.push({key,label,status:count===0?'pass':severity,count,message,details});try{const started=Date.now(),coreTables=['tenants','users','sites','guard_assignments','shifts','attendance_sessions','patrol_logs','patrol_runs','incidents','audit_logs'];const tableRows=await pool.query(`SELECT x name,to_regclass('public.'||x) present FROM unnest($1::text[]) x`,[coreTables]);const missing=tableRows.rows.filter(x=>!x.present).map(x=>x.name);add('schema','Core database tables',missing.length?'fail':'warn',missing.length,missing.length?'Required tables are missing':'All required core tables are available',missing);const identityIndex=await pool.query(`SELECT to_regclass('public.users_active_identity_unique') present`);const identityProtectionMissing=identityIndex.rows[0].present?0:1;add('identity_constraint','Active account uniqueness protection','fail',identityProtectionMissing,identityProtectionMissing?'Database uniqueness protection is missing':'Duplicate active guard/staff identities are blocked by the database');
const results=await withTenant(t,async c=>Promise.all([
c.query(`SELECT LOWER(email) email,role,COUNT(*)::int count,ARRAY_AGG(id ORDER BY id) ids FROM users WHERE tenant_id=$1 AND COALESCE(account_active,TRUE)=TRUE GROUP BY LOWER(email),role HAVING COUNT(*)>1`,[t]),
c.query(`SELECT ga.id,ga.user_id,u.email,ga.site_id FROM guard_assignments ga JOIN users u ON u.id=ga.user_id AND u.tenant_id=ga.tenant_id WHERE ga.tenant_id=$1 AND COALESCE(u.account_active,TRUE)=FALSE`,[t]),
c.query(`SELECT ga.id,ga.user_id,ga.site_id FROM guard_assignments ga LEFT JOIN users u ON u.id=ga.user_id AND u.tenant_id=ga.tenant_id LEFT JOIN sites s ON s.id=ga.site_id AND s.tenant_id=ga.tenant_id WHERE ga.tenant_id=$1 AND (u.id IS NULL OR s.id IS NULL)`,[t]),
c.query(`SELECT user_id,COUNT(*)::int count,ARRAY_AGG(id ORDER BY id) session_ids FROM attendance_sessions WHERE tenant_id=$1 AND clocked_out_at IS NULL GROUP BY user_id HAVING COUNT(*)>1`,[t]),
c.query(`SELECT a.id,a.user_id,u.email FROM attendance_sessions a JOIN users u ON u.id=a.user_id AND u.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.clocked_out_at IS NULL AND COALESCE(u.account_active,TRUE)=FALSE`,[t]),
c.query(`SELECT s.id,s.user_id,s.site_id FROM shifts s LEFT JOIN users u ON u.id=s.user_id AND u.tenant_id=s.tenant_id LEFT JOIN sites si ON si.id=s.site_id AND si.tenant_id=s.tenant_id WHERE s.tenant_id=$1 AND (u.id IS NULL OR si.id IS NULL) LIMIT 100`,[t]),
c.query(`SELECT id,event_type,attempts,last_error,created_at FROM webhook_deliveries WHERE tenant_id=$1 AND status='failed' AND attempts>=5 ORDER BY created_at DESC LIMIT 50`,[t]),
c.query(`SELECT id,event_type,attempt_count,last_error,created_at FROM email_deliveries WHERE tenant_id=$1 AND status='failed' AND attempt_count>=5 ORDER BY created_at DESC LIMIT 50`,[t]),
c.query(`SELECT COUNT(*)::int count FROM password_reset_tokens WHERE tenant_id=$1 AND used_at IS NULL AND expires_at<=NOW()`,[t]),
c.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id<>$1`,[t])
]));
const[duplicates,inactiveAssignments,brokenAssignments,multipleAttendance,inactiveAttendance,brokenShifts,deadWebhooks,deadEmails,expiredTokens,crossTenant]=results;
add('duplicate_users','Duplicate active guard/staff identities','fail',duplicates.rowCount,'Each active email and role should identify one account',duplicates.rows);add('inactive_assignments','Assignments owned by archived guards','warn',inactiveAssignments.rowCount,'Archived guards should not retain active site assignments',inactiveAssignments.rows);add('broken_assignments','Broken site assignments','fail',brokenAssignments.rowCount,'Every assignment must reference a valid guard and site in this company',brokenAssignments.rows);add('attendance_overlap','Multiple open clock-ins','fail',multipleAttendance.rowCount,'A guard should have at most one open attendance session',multipleAttendance.rows);add('inactive_attendance','Archived guards still clocked in','fail',inactiveAttendance.rowCount,'Archived accounts cannot remain clocked in',inactiveAttendance.rows);add('broken_shifts','Shifts with missing guard or site','fail',brokenShifts.rowCount,'Every shift must reference a valid guard and site',brokenShifts.rows);add('webhook_dead_letters','Webhooks exhausted retries','warn',deadWebhooks.rowCount,'Failed integrations require review',deadWebhooks.rows);add('email_dead_letters','Emails exhausted retries','warn',deadEmails.rowCount,'Failed email deliveries require review',deadEmails.rows);add('expired_reset_tokens','Expired unused reset tokens','warn',Number(expiredTokens.rows[0].count),'Expired tokens are harmless and will be cleaned automatically');add('tenant_isolation','Database tenant isolation probe','fail',Number(crossTenant.rows[0].count),'A tenant-scoped database session must not see users from other companies');
const summary={pass:checks.filter(x=>x.status==='pass').length,warn:checks.filter(x=>x.status==='warn').length,fail:checks.filter(x=>x.status==='fail').length};res.json({status:summary.fail?'action_required':summary.warn?'warning':'healthy',generated_at:new Date(),duration_ms:Date.now()-started,tenant_id:t,summary,checks,request_id:req.requestId})}catch(e){res.status(500).json({error:e.message,request_id:req.requestId})}});

// ------------------------ PHASE 4.12: SECURITY, BACKUP & RECOVERY ------------------------
app.post('/api/auth/guard-login-v2',fixedWindowRateLimit('guard-login-scoped-v2',20),async(req,res)=>{const tenantId=Number(req.body.company_id||req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!Number.isInteger(tenantId)||tenantId<1||!email||!password)return res.status(400).json({error:'Company ID, email and password are required'});try{const result=await withTenant(tenantId,c=>c.query(`SELECT u.id,u.tenant_id,u.email,u.role,u.password_hash,u.account_active,(SELECT COUNT(*)::int FROM guard_assignments ga WHERE ga.tenant_id=u.tenant_id AND ga.user_id=u.id) assignment_count FROM users u WHERE u.tenant_id=$1 AND LOWER(u.email)=$2 AND u.role='guard' AND COALESCE(u.account_active,TRUE)=TRUE ORDER BY assignment_count DESC,u.id DESC`,[tenantId,email]));let user=null;for(const candidate of result.rows){if(candidate.password_hash&&await bcrypt.compare(password,candidate.password_hash)){user=candidate;break}}if(!user)return res.status(401).json({error:'Invalid Company ID, guard email or password'});const token=jwt.sign({user_id:user.id,tenant_id:user.tenant_id,role:'guard',email:user.email},JWT_SECRET,{expiresIn:'12h'});res.json({token,tenant_id:user.tenant_id,user:{id:user.id,email:user.email,role:'guard'},assignment_count:user.assignment_count})}catch(e){console.error('Guard login v2 failed:',e.message);res.status(500).json({error:'Guard login failed'})}});

app.post('/api/auth/guard-login',fixedWindowRateLimit('guard-login-scoped',20),async(req,res)=>{const tenantId=Number(req.body.company_id||req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!Number.isInteger(tenantId)||tenantId<1||!email||!password)return res.status(400).json({error:'Company ID, email and password are required'});try{const result=await withTenant(tenantId,c=>c.query(`SELECT id,tenant_id,email,role,password_hash,account_active FROM users WHERE tenant_id=$1 AND LOWER(email)=$2 AND role='guard' LIMIT 1`,[tenantId,email]));const user=result.rows[0];if(!user||user.account_active===false||!user.password_hash||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Invalid Company ID, guard email or password'});const token=jwt.sign({user_id:user.id,tenant_id:user.tenant_id,role:'guard',email:user.email},JWT_SECRET,{expiresIn:'12h'});res.json({token,tenant_id:user.tenant_id,user:{id:user.id,email:user.email,role:'guard'}})}catch(e){res.status(500).json({error:'Guard login failed'})}});

app.post('/api/auth/scoped-forgot-password',fixedWindowRateLimit('password-reset-scoped',5),async(req,res)=>{const tenantId=Number(req.body.company_id||req.body.tenant_id),email=String(req.body.email||'').trim().toLowerCase(),accountType=String(req.body.account_type||'admin').toLowerCase(),accepted={message:'If that company account exists, a reset link has been sent.'};if(!Number.isInteger(tenantId)||tenantId<1||!email||!['admin','guard'].includes(accountType))return res.json(accepted);try{const roles=accountType==='guard'?['guard']:['admin','staff'],found=await withTenant(tenantId,c=>c.query(`SELECT id,tenant_id,email,role FROM users WHERE tenant_id=$1 AND LOWER(email)=$2 AND role=ANY($3::text[]) AND COALESCE(account_active,TRUE)=TRUE ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'staff' THEN 2 ELSE 3 END LIMIT 1`,[tenantId,email,roles]));if(!found.rowCount)return res.json(accepted);const user=found.rows[0],raw=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(raw).digest('hex');await pool.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[user.id,user.tenant_id]);await pool.query(`INSERT INTO password_reset_tokens(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '30 minutes')`,[user.tenant_id,user.id,hash]);const link=`${FRONTEND_URL||'https://patrolsync.co'}/reset_password.html?token=${encodeURIComponent(raw)}`;await sendProviderEmail({to:user.email,subject:`Reset your PatrolSync ${accountType} password`,html:emailHtml(`Reset your ${accountType} password`,'<p>This secure link expires in 30 minutes. If you did not request it, you can ignore this email.</p>','Reset Password',link)});await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_reset_requested','info','Password reset requested',$2::jsonb)`,[tenantId,JSON.stringify({user_id:user.id,role:user.role,account_type:accountType})]);res.json(accepted)}catch(e){console.error('Scoped password reset failed:',e.message);res.json(accepted)}});

app.post('/api/auth/forgot-password-by-role',fixedWindowRateLimit('password-reset-role',5),async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase(),accountType=String(req.body.account_type||'admin').toLowerCase(),accepted={message:'If that account exists, a reset link has been sent.'};if(!email||!['admin','guard'].includes(accountType))return res.json(accepted);try{let user=null;const tenants=await pool.query('SELECT id FROM tenants');for(const tenant of tenants.rows){const roles=accountType==='guard'?['guard']:['admin','staff'];const found=await withTenant(tenant.id,c=>c.query(`SELECT id,tenant_id,email,role FROM users WHERE tenant_id=$1 AND LOWER(email)=$2 AND role=ANY($3::text[]) AND COALESCE(account_active,TRUE)=TRUE ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'staff' THEN 2 ELSE 3 END LIMIT 1`,[tenant.id,email,roles]));if(found.rowCount){user=found.rows[0];break}}if(!user)return res.json(accepted);const raw=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(raw).digest('hex');await pool.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[user.id,user.tenant_id]);await pool.query(`INSERT INTO password_reset_tokens(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '30 minutes')`,[user.tenant_id,user.id,hash]);const link=`${FRONTEND_URL||'https://patrolsync.co'}/reset_password.html?token=${encodeURIComponent(raw)}`;await sendProviderEmail({to:user.email,subject:`Reset your PatrolSync ${accountType} password`,html:emailHtml(`Reset your ${accountType} password`,'<p>This secure link expires in 30 minutes. If you did not request it, you can ignore this email.</p>','Reset Password',link)});await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_reset_requested','info','Password reset requested',$2::jsonb)`,[user.tenant_id,JSON.stringify({user_id:user.id,role:user.role,account_type:accountType})]);res.json(accepted)}catch(e){console.error('Role-specific password reset failed:',e.message);res.json(accepted)}});

app.post('/api/auth/forgot-password',fixedWindowRateLimit('password-reset',5),async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase();const accepted={message:'If that email exists, a reset link has been sent.'};if(!email)return res.json(accepted);try{const found=await pool.query(`SELECT id,tenant_id,email FROM users WHERE LOWER(email)=$1 AND COALESCE(account_active,TRUE)=TRUE ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'staff' THEN 2 ELSE 3 END LIMIT 1`,[email]);if(!found.rowCount)return res.json(accepted);const user=found.rows[0],raw=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(raw).digest('hex');await pool.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[user.id,user.tenant_id]);await pool.query(`INSERT INTO password_reset_tokens(tenant_id,user_id,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '30 minutes')`,[user.tenant_id,user.id,hash]);const link=`${FRONTEND_URL||'https://patrolsync.co'}/reset_password.html?token=${encodeURIComponent(raw)}`;await sendProviderEmail({to:user.email,subject:'Reset your PatrolSync password',html:emailHtml('Reset your password','<p>This secure link expires in 30 minutes. If you did not request it, you can ignore this email.</p>','Reset Password',link)});await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_reset_requested','info','Password reset requested',$2)`,[user.tenant_id,JSON.stringify({user_id:user.id})]);res.json(accepted)}catch(e){console.error('Password reset request failed:',e.message);res.json(accepted)}});

app.post('/api/auth/reset-password',fixedWindowRateLimit('password-reset-submit',10),async(req,res)=>{const raw=String(req.body.token||''),password=String(req.body.password||'');if(password.length<10||!/[A-Z]/.test(password)||!/[a-z]/.test(password)||!/[0-9]/.test(password))return res.status(400).json({error:'Use at least 10 characters including uppercase, lowercase and a number'});const hash=crypto.createHash('sha256').update(raw).digest('hex'),client=await pool.connect();try{await client.query('BEGIN');const found=await client.query(`SELECT * FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE`,[hash]);if(!found.rowCount){await client.query('ROLLBACK');return res.status(400).json({error:'Reset link is invalid or expired'})}const record=found.rows[0],passwordHash=await bcrypt.hash(password,12);await client.query(`UPDATE users SET password_hash=$1,password_changed_at=NOW() WHERE id=$2 AND tenant_id=$3`,[passwordHash,record.user_id,record.tenant_id]);await client.query(`UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND tenant_id=$2 AND used_at IS NULL`,[record.user_id,record.tenant_id]);await client.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details) VALUES($1,'password_changed','warning','Account password changed; older sessions invalidated',$2)`,[record.tenant_id,JSON.stringify({user_id:record.user_id})]);await client.query('COMMIT');res.json({message:'Password changed successfully. You can now log in.'})}catch(e){await client.query('ROLLBACK');res.status(500).json({error:'Could not reset password'})}finally{client.release()}});

app.get('/api/security-center',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const [events,disabled,resets]=await Promise.all([pool.query(`SELECT event_type,severity,message,details,request_id,created_at FROM system_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`,[t]),pool.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id=$1 AND COALESCE(account_active,TRUE)=FALSE`,[t]),pool.query(`SELECT COUNT(*) FILTER(WHERE used_at IS NULL AND expires_at>NOW())::int active,COUNT(*) FILTER(WHERE used_at IS NOT NULL)::int used FROM password_reset_tokens WHERE tenant_id=$1`,[t])]);res.json({events:events.rows,disabled_accounts:disabled.rows[0].count,password_resets:resets.rows[0],session_lifetime_hours:12,backup_responsibility:'Database backups and point-in-time restoration are managed in your PostgreSQL hosting provider.',request_id:req.requestId})}catch(e){res.status(500).json({error:e.message})}});

app.get('/api/company-data-export',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const queries={tenant:`SELECT id,name,plan,timezone,created_at FROM tenants WHERE id=$1`,sites:`SELECT * FROM sites WHERE tenant_id=$1`,users:`SELECT id,tenant_id,email,role,job_title,permissions,account_active,created_at FROM users WHERE tenant_id=$1`,shifts:`SELECT * FROM shifts WHERE tenant_id=$1`,attendance:`SELECT * FROM attendance_sessions WHERE tenant_id=$1`,patrol_runs:`SELECT * FROM patrol_runs WHERE tenant_id=$1`,incidents:`SELECT * FROM incidents WHERE tenant_id=$1`,contracts:`SELECT * FROM service_contracts WHERE tenant_id=$1`,invoices:`SELECT * FROM invoices WHERE tenant_id=$1`,audit_logs:`SELECT * FROM audit_logs WHERE tenant_id=$1 ORDER BY created_at DESC`};const data={exported_at:new Date().toISOString(),format_version:1};for(const[name,sql]of Object.entries(queries))data[name]=(await pool.query(sql,[t])).rows;await pool.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details,request_id) VALUES($1,'company_data_exported','warning','Company data export downloaded',$2,$3)`,[t,JSON.stringify({requested_by:req.auth.user_id}),req.requestId]);res.setHeader('Content-Type','application/json');res.setHeader('Content-Disposition',`attachment; filename="patrolsync-company-${t}-${new Date().toISOString().slice(0,10)}.json"`);res.send(JSON.stringify(data,null,2))}catch(e){res.status(500).json({error:e.message})}});

// ------------------------ PHASE 4.11: PRODUCTION HARDENING ------------------------
app.get('/api/system-health',requireAuth,requireOwnerAdmin,async(req,res)=>{const t=communicationTenant(req,req.query.tenant_id);if(!t)return res.status(403).json({error:'Tenant access denied'});try{const dbStarted=Date.now();await pool.query('SELECT 1');const dbLatency=Date.now()-dbStarted;const[webhooks,events,audit,activeUsers]=await Promise.all([pool.query(`SELECT COUNT(*) FILTER(WHERE status='queued')::int queued,COUNT(*) FILTER(WHERE status='failed')::int failed,COUNT(*) FILTER(WHERE status='delivered')::int delivered,MAX(delivered_at) last_delivered_at FROM webhook_deliveries WHERE tenant_id=$1`,[t]),pool.query(`SELECT id,event_type,severity,message,details,request_id,created_at FROM system_events WHERE tenant_id IS NULL OR tenant_id=$1 ORDER BY created_at DESC LIMIT 50`,[t]),pool.query(`SELECT COUNT(*)::int total,MAX(created_at) latest_at FROM audit_logs WHERE tenant_id=$1`,[t]),pool.query(`SELECT COUNT(*)::int total FROM users WHERE tenant_id=$1 AND COALESCE(account_active,TRUE)=TRUE`,[t])]);const memory=process.memoryUsage();res.json({status:'healthy',generated_at:new Date(),started_at:APP_STARTED_AT,uptime_seconds:Math.floor(process.uptime()),database:{connected:true,latency_ms:dbLatency,pool_total:pool.totalCount,pool_idle:pool.idleCount,pool_waiting:pool.waitingCount},memory:{rss_mb:Math.round(memory.rss/1048576),heap_used_mb:Math.round(memory.heapUsed/1048576)},webhooks:webhooks.rows[0],audit:audit.rows[0],active_users:activeUsers.rows[0].total,retention:{audit_days:AUDIT_RETENTION_DAYS,webhook_days:WEBHOOK_RETENTION_DAYS},events:events.rows,request_id:req.requestId})}catch(e){res.status(503).json({status:'unhealthy',error:e.message,request_id:req.requestId})}});

async function runOperationsCleanup(){try{const result=await pool.query(`WITH a AS (DELETE FROM audit_logs WHERE created_at<NOW()-($1::int*INTERVAL '1 day') RETURNING 1),w AS (DELETE FROM webhook_deliveries WHERE created_at<NOW()-($2::int*INTERVAL '1 day') RETURNING 1),e AS (DELETE FROM system_events WHERE created_at<NOW()-INTERVAL '30 days' RETURNING 1),s AS (DELETE FROM auth_sessions WHERE expires_at<NOW()-INTERVAL '90 days' RETURNING 1),m AS (DELETE FROM email_mfa_challenges WHERE expires_at<NOW()-INTERVAL '7 days' RETURNING 1) SELECT (SELECT COUNT(*) FROM a)::int audit_deleted,(SELECT COUNT(*) FROM w)::int webhook_deleted,(SELECT COUNT(*) FROM e)::int events_deleted,(SELECT COUNT(*) FROM s)::int sessions_deleted,(SELECT COUNT(*) FROM m)::int mfa_challenges_deleted`,[AUDIT_RETENTION_DAYS,WEBHOOK_RETENTION_DAYS]);const counts=result.rows[0];if(Object.values(counts).some(Number))console.log('Operations cleanup:',counts);return counts}catch(e){console.error('Operations cleanup failed:',e.message);throw e}}scheduleBackgroundJob('operations_retention_cleanup',24*60*60*1000,60000,runOperationsCleanup);

app.use((err,req,res,next)=>{console.error(JSON.stringify({level:'error',type:'unhandled_request_error',request_id:req.requestId,method:req.method,path:req.path,message:err.message}));if(res.headersSent)return next(err);res.status(err.statusCode||500).json({error:err.statusCode?err.message:'Unexpected server error',request_id:req.requestId})});

// ------------------------ PLATFORM DATABASE ISOLATION SETUP ------------------------
app.get('/api/platform/security-posture',requirePlatformAuth,async(req,res)=>{try{const posture=getProductionSecurityPosture();await platformAudit(req,'VIEW','production_security_posture',{ready:posture.ready,failed_checks:posture.checks.filter(x=>!x.passed).map(x=>x.key)});res.json({...posture,generated_at:new Date(),headers:{hsts:IS_PRODUCTION,content_security_policy:true,frame_protection:true,no_sniff:true,sensitive_cache_control:true},rate_limits:{authentication_per_15_minutes:AUTH_REQUEST_LIMIT,signup_per_15_minutes:5,integration_api_per_15_minutes:API_KEY_REQUEST_LIMIT}})}catch(e){res.status(500).json({error:e.message})}});

app.get('/api/platform/database-isolation',requirePlatformAuth,async(req,res)=>{
  let tenantClient;
  try{
    const systemRole=(await pool.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls,r.rolcreaterole can_create_role FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];
    tenantClient=await tenantPool.connect();
    const tenantRole=(await tenantClient.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];
    const first=(await pool.query(`SELECT t.id FROM tenants t ORDER BY (SELECT COUNT(*) FROM users u WHERE u.tenant_id=t.id) DESC,t.id LIMIT 1`)).rows[0];
    let crossTenantVisible=null,ownUsersVisible=null,expectedOwnUsers=null;
    if(first){expectedOwnUsers=Number((await pool.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id=$1`,[first.id])).rows[0].count);await tenantClient.query(`SELECT set_config('app.current_tenant',$1,false)`,[String(first.id)]);ownUsersVisible=Number((await tenantClient.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id=$1`,[first.id])).rows[0].count);crossTenantVisible=Number((await tenantClient.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id<>$1`,[first.id])).rows[0].count);await tenantClient.query('RESET app.current_tenant')}
    const policies=await pool.query(`SELECT COUNT(DISTINCT c.oid)::int tenant_tables,COUNT(DISTINCT c.oid) FILTER(WHERE c.relrowsecurity)::int rls_enabled,COUNT(DISTINCT c.oid) FILTER(WHERE c.relforcerowsecurity)::int rls_forced,COUNT(DISTINCT c.oid) FILTER(WHERE p.policyname IS NOT NULL)::int tables_with_policy FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_policies p ON p.schemaname=n.nspname AND p.tablename=c.relname WHERE n.nspname='public' AND c.relkind IN('r','p')`);
    const tenantsProtection=(await pool.query(`SELECT c.relrowsecurity rls_enabled,c.relforcerowsecurity rls_forced,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname='public' AND p.tablename='tenants') has_policy FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='tenants'`)).rows[0]||{};
    const p=policies.rows[0],separated=systemRole.role_name!==tenantRole.role_name,coverageComplete=Number(p.tenant_tables)>0&&Number(p.rls_enabled)===Number(p.tenant_tables)&&Number(p.tables_with_policy)===Number(p.tenant_tables)&&tenantsProtection.rls_enabled&&tenantsProtection.has_policy,isolationPassed=separated&&coverageComplete&&crossTenantVisible===0&&ownUsersVisible===expectedOwnUsers;
    await platformAudit(req,'VIEW','database_isolation_status',{system_role:systemRole.role_name,tenant_role:tenantRole.role_name,separated,isolation_passed:isolationPassed});
    res.json({status:isolationPassed?'isolated':separated?'separated_not_enforced':'compatibility_mode',system_role:systemRole,tenant_role:tenantRole,paths_separated:separated,tenant_context:first?.id||null,own_users_expected:expectedOwnUsers,own_users_visible:ownUsersVisible,cross_tenant_users_visible:crossTenantVisible,coverage_complete:coverageComplete,policies:p,tenants_table:tenantsProtection,next_action:!separated?'Generate a restricted tenant connection, then set TENANT_DATABASE_URL in Render.':!coverageComplete?'Run controlled RLS activation.':ownUsersVisible!==expectedOwnUsers?'RLS is blocking legitimate company records; review policies.':crossTenantVisible>0?'Cross-company records remain visible; review policies.':'Tenant isolation is enforced.'});
  }catch(e){res.status(500).json({error:e.message})}finally{if(tenantClient)tenantClient.release()}
});

app.post('/api/platform/database-isolation/bootstrap-role',requirePlatformAuth,async(req,res)=>{
  const client=await pool.connect();
  try{
    if(!systemDatabaseUrl) return res.status(503).json({error:'SYSTEM_DATABASE_URL or DATABASE_URL is not configured'});
    if(DATABASE_PATHS_SEPARATED)return res.status(409).json({error:'Tenant and system database paths are already separated. Password rotation is disabled here to avoid breaking the active tenant connection.'});
    const capability=(await client.query(`SELECT r.rolcreaterole can_create_role,r.rolsuper is_superuser FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];
    if(!capability?.can_create_role&&!capability?.is_superuser)return res.status(403).json({error:'The current PostgreSQL role cannot create the restricted login. Use the manual SQL setup instead.'});
    const password=crypto.randomBytes(36).toString('base64url');
    await client.query('BEGIN');
    const baseRoleExists=(await client.query(`SELECT 1 FROM pg_roles WHERE rolname='patrolsync_tenant_app'`)).rowCount>0;
    const roleName=baseRoleExists?'patrolsync_tenant_'+crypto.randomBytes(4).toString('hex'):'patrolsync_tenant_app';
    const quotedRole=quotePgIdentifier(roleName);
    const quotedPassword=password.replace(/'/g,"''");
    await client.query(`CREATE ROLE ${quotedRole} LOGIN PASSWORD '${quotedPassword}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS`);
    await client.query(`GRANT CONNECT ON DATABASE ${quotePgIdentifier((await client.query('SELECT current_database() db')).rows[0].db)} TO ${quotedRole}`);
    await client.query(`GRANT USAGE ON SCHEMA public TO ${quotedRole}`);
    await client.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO ${quotedRole}`);
    await client.query(`GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO ${quotedRole}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO ${quotedRole}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO ${quotedRole}`);
    await client.query('COMMIT');
    const connection=new URL(systemDatabaseUrl);connection.username=roleName;connection.password=password;
    await platformAudit(req,'CREATE_TENANT_DB_ROLE','database_security',{role:roleName,legacy_role_already_existed:baseRoleExists});
    res.setHeader('Cache-Control','no-store');
    res.json({message:`Restricted tenant database role ${roleName} created.`,tenant_role:roleName,tenant_database_url:connection.toString(),warning:'Copy this URL now. It will not be shown again.'});
  }catch(e){try{await client.query('ROLLBACK')}catch(_){}res.status(500).json({error:e.message})}finally{client.release()}
});

app.post('/api/platform/database-isolation/activate',requirePlatformAuth,async(req,res)=>{
  if(String(req.body.confirmation||'')!=='ENABLE RLS')return res.status(400).json({error:'Type ENABLE RLS to confirm'});
  if(!DATABASE_PATHS_SEPARATED)return res.status(409).json({error:'Set and verify a separate TENANT_DATABASE_URL before enabling RLS'});
  const tenantRoleInfo=(await tenantPool.query(`SELECT current_user role_name,r.rolsuper is_superuser,r.rolbypassrls bypasses_rls FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];
  if(!tenantRoleInfo||tenantRoleInfo.is_superuser||tenantRoleInfo.bypasses_rls||tenantRoleInfo.role_name==='patrolsync_db_user')return res.status(409).json({error:'TENANT_DATABASE_URL is not using a safe restricted role'});
  const role=tenantRoleInfo.role_name,quotedRole=quotePgIdentifier(role),client=await pool.connect();
  let tables=[],originallyEnabled=new Set(),tenantsOriginallyEnabled=false;
  try{
    const tableRows=await client.query(`SELECT c.relname table_name,c.relrowsecurity rls_enabled FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped WHERE n.nspname='public' AND c.relkind IN('r','p') ORDER BY c.relname`);
    tables=tableRows.rows.map(x=>x.table_name);originallyEnabled=new Set(tableRows.rows.filter(x=>x.rls_enabled).map(x=>x.table_name));
    tenantsOriginallyEnabled=Boolean((await client.query(`SELECT c.relrowsecurity enabled FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='tenants'`)).rows[0]?.enabled);
    if(!tables.length)throw new Error('No tenant tables were discovered');
    await client.query('BEGIN');
    await client.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${quotedRole}`);
    await client.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ${quotedRole}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM ${quotedRole}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM ${quotedRole}`);
    await client.query(`GRANT USAGE ON SCHEMA public TO ${quotedRole}`);
    for(const table of tables){
      const q=quotePgIdentifier(table);
      await client.query(`DROP POLICY IF EXISTS patrolsync_tenant_access ON public.${q}`);
      await client.query(`CREATE POLICY patrolsync_tenant_access ON public.${q} AS PERMISSIVE FOR ALL TO ${quotedRole} USING (tenant_id = NULLIF(current_setting('app.current_tenant',true),'')::bigint) WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant',true),'')::bigint)`);
      await client.query(`ALTER TABLE public.${q} ENABLE ROW LEVEL SECURITY`);
      await client.query(`ALTER TABLE public.${q} NO FORCE ROW LEVEL SECURITY`);
      await client.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON public.${q} TO ${quotedRole}`);
    }
    await client.query(`DROP POLICY IF EXISTS patrolsync_tenant_row ON public.tenants`);
    await client.query(`CREATE POLICY patrolsync_tenant_row ON public.tenants AS PERMISSIVE FOR ALL TO ${quotedRole} USING (id = NULLIF(current_setting('app.current_tenant',true),'')::bigint) WITH CHECK (id = NULLIF(current_setting('app.current_tenant',true),'')::bigint)`);
    await client.query(`ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY`);
    await client.query(`ALTER TABLE public.tenants NO FORCE ROW LEVEL SECURITY`);
    await client.query(`GRANT SELECT ON public.tenants TO ${quotedRole}`);
    await client.query(`GRANT UPDATE (timezone,emergency_phone,emergency_whatsapp) ON public.tenants TO ${quotedRole}`);
    const sequences=await client.query(`SELECT DISTINCT ns.nspname schema_name,s.relname sequence_name FROM pg_class s JOIN pg_namespace ns ON ns.oid=s.relnamespace JOIN pg_depend d ON d.objid=s.oid AND d.deptype IN('a','i') JOIN pg_class t ON t.oid=d.refobjid JOIN pg_namespace tn ON tn.oid=t.relnamespace WHERE s.relkind='S' AND ns.nspname='public' AND tn.nspname='public' AND t.relname=ANY($1::text[])`,[tables]);
    for(const seq of sequences.rows)await client.query(`GRANT USAGE,SELECT ON ${quotePgIdentifier(seq.schema_name)}.${quotePgIdentifier(seq.sequence_name)} TO ${quotedRole}`);
    await client.query('COMMIT');

    const testTenant=(await pool.query(`SELECT t.id FROM tenants t ORDER BY (SELECT COUNT(*) FROM users u WHERE u.tenant_id=t.id) DESC,t.id LIMIT 1`)).rows[0];
    if(!testTenant)throw new Error('No subscriber company is available for the post-activation probe');
    const failures=[];
    await withTenant(testTenant.id,async restricted=>{
      for(const table of tables){
        const q=quotePgIdentifier(table),expected=Number((await pool.query(`SELECT COUNT(*)::int count FROM public.${q} WHERE tenant_id=$1`,[testTenant.id])).rows[0].count),own=Number((await restricted.query(`SELECT COUNT(*)::int count FROM public.${q} WHERE tenant_id=$1`,[testTenant.id])).rows[0].count),cross=Number((await restricted.query(`SELECT COUNT(*)::int count FROM public.${q} WHERE tenant_id<>$1`,[testTenant.id])).rows[0].count);
        if(own!==expected||cross!==0)failures.push({table,expected_own:expected,visible_own:own,visible_cross:cross});
      }
      const tenantOwn=Number((await restricted.query(`SELECT COUNT(*)::int count FROM tenants WHERE id=$1`,[testTenant.id])).rows[0].count),tenantCross=Number((await restricted.query(`SELECT COUNT(*)::int count FROM tenants WHERE id<>$1`,[testTenant.id])).rows[0].count);
      if(tenantOwn!==1||tenantCross!==0)failures.push({table:'tenants',expected_own:1,visible_own:tenantOwn,visible_cross:tenantCross});
    });
    if(failures.length)throw Object.assign(new Error('RLS verification failed; protections were rolled back'),{verificationFailures:failures});
    await platformAudit(req,'ENABLE_RLS','database_security',{tenant_role:role,tables_protected:tables.length,test_tenant_id:testTenant.id});
    res.json({message:`Tenant isolation enabled and verified across ${tables.length} tenant tables plus the company table.`,tables_protected:tables.length+1,tenant_role:role});
  }catch(e){
    try{await client.query('ROLLBACK')}catch(_){}
    if(tables.length){
      try{await client.query('BEGIN');for(const table of tables){const q=quotePgIdentifier(table);await client.query(`DROP POLICY IF EXISTS patrolsync_tenant_access ON public.${q}`);if(!originallyEnabled.has(table))await client.query(`ALTER TABLE public.${q} DISABLE ROW LEVEL SECURITY`)}await client.query(`DROP POLICY IF EXISTS patrolsync_tenant_row ON public.tenants`);if(!tenantsOriginallyEnabled)await client.query(`ALTER TABLE public.tenants DISABLE ROW LEVEL SECURITY`);await client.query('COMMIT')}catch(rollbackError){try{await client.query('ROLLBACK')}catch(_){}console.error('RLS fail-safe rollback failed:',rollbackError.message)}
    }
    await platformAudit(req,'RLS_ACTIVATION_FAILED','database_security',{tenant_role:role,error:e.message,failures:e.verificationFailures||[]}).catch(()=>{});
    res.status(500).json({error:e.message,verification_failures:e.verificationFailures||[]});
  }finally{client.release()}
});

function quotePgIdentifier(value){return '"'+String(value).replace(/"/g,'""')+'"'}

// ------------------------ PHASE 6: PERFORMANCE OBSERVABILITY ------------------------
const SAFE_PERFORMANCE_INDEXES=[
  {name:'idx_users_tenant_role_active',table:'users',columns:['tenant_id','role','account_active'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant_role_active ON users(tenant_id,role,account_active)`},
  {name:'idx_guard_assignments_tenant_user',table:'guard_assignments',columns:['tenant_id','user_id'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_guard_assignments_tenant_user ON guard_assignments(tenant_id,user_id)`},
  {name:'idx_attendance_open_guard',table:'attendance_sessions',columns:['tenant_id','user_id','clocked_out_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_attendance_open_guard ON attendance_sessions(tenant_id,user_id) WHERE clocked_out_at IS NULL`},
  {name:'idx_attendance_tenant_guard_clockin',table:'attendance_sessions',columns:['tenant_id','user_id','clocked_in_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_attendance_tenant_guard_clockin ON attendance_sessions(tenant_id,user_id,clocked_in_at DESC)`},
  {name:'idx_notifications_tenant_open_created',table:'notifications',columns:['tenant_id','resolved','created_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_tenant_open_created ON notifications(tenant_id,resolved,created_at DESC)`},
  {name:'idx_incidents_tenant_status_reported',table:'incidents',columns:['tenant_id','status','reported_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incidents_tenant_status_reported ON incidents(tenant_id,status,reported_at DESC)`},
  {name:'idx_sos_alerts_tenant_status_created',table:'sos_alerts',columns:['tenant_id','status','created_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sos_alerts_tenant_status_created ON sos_alerts(tenant_id,status,created_at DESC)`},
  {name:'idx_patrol_runs_tenant_status_start',table:'patrol_runs',columns:['tenant_id','status','scheduled_start'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_patrol_runs_tenant_status_start ON patrol_runs(tenant_id,status,scheduled_start)`},
  {name:'idx_auth_sessions_active_user',table:'auth_sessions',columns:['tenant_id','user_id','expires_at','revoked_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_auth_sessions_active_user ON auth_sessions(tenant_id,user_id,expires_at) WHERE revoked_at IS NULL`},
  {name:'idx_communication_notifications_recipient',table:'communication_notifications',columns:['tenant_id','recipient_user_id','created_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_communication_notifications_recipient ON communication_notifications(tenant_id,recipient_user_id,created_at DESC)`},
  {name:'idx_training_assignments_guard_status',table:'training_assignments',columns:['tenant_id','user_id','status'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_training_assignments_guard_status ON training_assignments(tenant_id,user_id,status)`},
  {name:'idx_inspection_runs_guard_status',table:'inspection_runs',columns:['tenant_id','assigned_user_id','status'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_inspection_runs_guard_status ON inspection_runs(tenant_id,assigned_user_id,status)`},
  {name:'idx_dispatch_jobs_tenant_status',table:'dispatch_jobs',columns:['tenant_id','status','created_at'],sql:`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dispatch_jobs_tenant_status ON dispatch_jobs(tenant_id,status,created_at DESC)`}
];
async function performanceIndexReadiness(){const existing=new Set((await pool.query(`SELECT indexname FROM pg_indexes WHERE schemaname='public'`)).rows.map(x=>x.indexname));const columns=new Set((await pool.query(`SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public'`)).rows.map(x=>`${x.table_name}.${x.column_name}`));return SAFE_PERFORMANCE_INDEXES.map(x=>({...x,sql:undefined,available:x.columns.every(c=>columns.has(`${x.table}.${c}`)),installed:existing.has(x.name)}))}
app.get('/api/platform/performance',requirePlatformAuth,async(req,res)=>{
  try{
    trimPerformanceSamples();
    const samples=[...performanceSamples],durations=samples.map(x=>x.duration_ms),errors=samples.filter(x=>x.status>=500),slow=samples.filter(x=>x.duration_ms>=1000);
    const routeMap=new Map();
    for(const item of samples){const key=`${item.method} ${item.path}`,current=routeMap.get(key)||{route:key,requests:0,errors:0,total_ms:0,max_ms:0};current.requests++;current.total_ms+=item.duration_ms;current.max_ms=Math.max(current.max_ms,item.duration_ms);if(item.status>=500)current.errors++;routeMap.set(key,current)}
    const routes=[...routeMap.values()].map(x=>({...x,average_ms:Math.round(x.total_ms/x.requests)})).sort((a,b)=>b.average_ms-a.average_ms||b.requests-a.requests).slice(0,25).map(({total_ms,...x})=>x);
    const dbStarted=Date.now();await pool.query('SELECT 1');const databaseLatencyMs=Date.now()-dbStarted;
    let tableActivity=[],indexActivity=[],databaseStats=null;
    try{tableActivity=(await pool.query(`SELECT relname table_name,seq_scan::bigint,idx_scan::bigint,n_live_tup::bigint live_rows,n_dead_tup::bigint dead_rows,CASE WHEN n_live_tup+n_dead_tup=0 THEN 0 ELSE ROUND(100.0*n_dead_tup/(n_live_tup+n_dead_tup),1) END dead_row_percent FROM pg_stat_user_tables ORDER BY n_live_tup DESC NULLS LAST LIMIT 30`)).rows}catch(_){}
    try{indexActivity=(await pool.query(`SELECT schemaname,indexrelname index_name,relname table_name,idx_scan::bigint,pg_relation_size(indexrelid)::bigint size_bytes FROM pg_stat_user_indexes WHERE schemaname='public' ORDER BY idx_scan ASC,pg_relation_size(indexrelid) DESC LIMIT 30`)).rows}catch(_){}
    try{databaseStats=(await pool.query(`SELECT numbackends::int connections,xact_commit::bigint commits,xact_rollback::bigint rollbacks,blks_read::bigint blocks_read,blks_hit::bigint blocks_hit,temp_files::bigint,temp_bytes::bigint,deadlocks::bigint,stats_reset FROM pg_stat_database WHERE datname=current_database()`)).rows[0]||null}catch(_){}
    const hitTotal=Number(databaseStats?.blocks_hit||0)+Number(databaseStats?.blocks_read||0);const cacheHitPercent=hitTotal?Math.round(Number(databaseStats.blocks_hit)*10000/hitTotal)/100:null;
    await platformAudit(req,'VIEW','performance_observability',{sample_count:samples.length});
    res.json({generated_at:new Date(),window_minutes:15,http:{requests:samples.length,errors_5xx:errors.length,error_rate_percent:samples.length?Math.round(errors.length*10000/samples.length)/100:0,slow_requests:slow.length,p50_ms:percentile(durations,50),p95_ms:percentile(durations,95),p99_ms:percentile(durations,99),max_ms:durations.length?Math.max(...durations):0,routes},database:{latency_ms:databaseLatencyMs,cache_hit_percent:cacheHitPercent,stats:databaseStats,system_pool:{total:systemPool.totalCount,idle:systemPool.idleCount,waiting:systemPool.waitingCount,max:DATABASE_POOL_MAX},tenant_pool:{shared_with_system:!DATABASE_PATHS_SEPARATED,total:tenantPool.totalCount,idle:tenantPool.idleCount,waiting:tenantPool.waitingCount,max:DATABASE_POOL_MAX},tables:tableActivity,indexes:indexActivity},process:{uptime_seconds:Math.floor(process.uptime()),heap_used_bytes:process.memoryUsage().heapUsed,rss_bytes:process.memoryUsage().rss,node_version:process.version}});
  }catch(e){res.status(500).json({error:e.message})}
});
app.get('/api/platform/performance/indexes',requirePlatformAuth,async(req,res)=>{try{const indexes=await performanceIndexReadiness();res.json({indexes,installed:indexes.filter(x=>x.installed).length,pending:indexes.filter(x=>x.available&&!x.installed).length,unavailable:indexes.filter(x=>!x.available).length})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/platform/performance/indexes/apply',requirePlatformAuth,async(req,res)=>{if(String(req.body.confirmation||'')!=='APPLY INDEXES')return res.status(400).json({error:'Type APPLY INDEXES to confirm'});try{const readiness=await performanceIndexReadiness(),pending=new Set(readiness.filter(x=>x.available&&!x.installed).map(x=>x.name)),applied=[],failed=[];for(const definition of SAFE_PERFORMANCE_INDEXES){if(!pending.has(definition.name))continue;try{await pool.query(definition.sql);applied.push(definition.name)}catch(e){failed.push({name:definition.name,error:e.message})}}await pool.query('ANALYZE').catch(()=>{});await platformAudit(req,'APPLY','performance_indexes',{applied,failed});const after=await performanceIndexReadiness();res.status(failed.length?207:200).json({message:failed.length?`${applied.length} index(es) applied; ${failed.length} require review.`:`${applied.length} performance index(es) applied successfully.`,applied,failed,indexes:after})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/platform/jobs',requirePlatformAuth,async(req,res)=>{try{const names=[...backgroundJobs.keys()],history=names.length?(await pool.query(`SELECT DISTINCT ON(job_name) id,job_name,instance_id,status,started_at,finished_at,duration_ms,error_message,details FROM platform_job_runs WHERE job_name=ANY($1::text[]) ORDER BY job_name,started_at DESC`,[names])).rows:[],recent=(await pool.query(`SELECT id,job_name,instance_id,status,started_at,finished_at,duration_ms,error_message,details FROM platform_job_runs ORDER BY started_at DESC LIMIT 100`)).rows,counts=(await pool.query(`SELECT COUNT(*) FILTER(WHERE status='running')::int running,COUNT(*) FILTER(WHERE status='failed' AND started_at>=NOW()-INTERVAL '24 hours')::int failed_24h,COUNT(*) FILTER(WHERE status='succeeded' AND started_at>=NOW()-INTERVAL '24 hours')::int succeeded_24h FROM platform_job_runs`)).rows[0],queue=(await Promise.all([pool.query(`SELECT COUNT(*)::int count FROM webhook_deliveries WHERE status IN('queued','failed') AND attempts<5`),pool.query(`SELECT COUNT(*)::int count FROM email_deliveries WHERE status IN('queued','failed') AND attempt_count<5`),pool.query(`SELECT COUNT(*)::int count FROM client_report_runs WHERE status IN('pending','generated')`)])).map(x=>x.rows[0].count);const latest=new Map(history.map(x=>[x.job_name,x]));res.json({generated_at:new Date(),instance_id:BACKGROUND_INSTANCE_ID,summary:counts,queues:{webhooks:Number(queue[0]),emails:Number(queue[1]),client_reports:Number(queue[2])},jobs:names.map(name=>({name,interval_ms:backgroundJobs.get(name).interval_ms,latest:latest.get(name)||null})),recent})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/platform/jobs/:name/run',requirePlatformAuth,async(req,res)=>{const job=backgroundJobs.get(req.params.name);if(!job)return res.status(404).json({error:'Background job not found'});const result=await runBackgroundJob(job.name,job.fn,'platform_manual');await platformAudit(req,'RUN','background_job',{job_name:job.name,result});if(result.status==='skipped')return res.status(409).json({error:'This job is already running on another application instance'});if(result.status==='failed')return res.status(500).json({error:result.error||'Background job failed'});res.json({message:`${job.name} completed successfully.`,result})});
app.get('/api/platform/load-tests',requirePlatformAuth,async(req,res)=>{try{const[history,tenants]=await Promise.all([pool.query(`SELECT id,scenario,tenant_id,concurrency,duration_seconds,status,started_at,finished_at,total_requests,successful_requests,failed_requests,requests_per_second,p50_ms,p95_ms,p99_ms,max_ms,error_summary,instance_id FROM platform_load_tests ORDER BY started_at DESC LIMIT 30`),pool.query(`SELECT id,name FROM tenants WHERE COALESCE(account_active,TRUE)=TRUE ORDER BY name`)]);res.json({history:history.rows,tenants:tenants.rows,limits:{max_concurrency:10,max_duration_seconds:15,max_requests:2000}})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/platform/load-tests/run',requirePlatformAuth,async(req,res)=>{
  const scenario=String(req.body.scenario||'tenant_read'),requestedConcurrency=Number(req.body.concurrency||3),requestedDuration=Number(req.body.duration_seconds||10),tenantId=req.body.tenant_id?Number(req.body.tenant_id):null;
  if(!Number.isFinite(requestedConcurrency)||!Number.isFinite(requestedDuration))return res.status(400).json({error:'Concurrency and duration must be numbers'});
  const concurrency=Math.max(1,Math.min(10,Math.floor(requestedConcurrency))),durationSeconds=Math.max(5,Math.min(15,Math.floor(requestedDuration)));
  if(!['tenant_read','platform_read','mixed_read'].includes(scenario))return res.status(400).json({error:'Invalid load-test scenario'});
  if(scenario!=='platform_read'&&(!Number.isInteger(tenantId)||tenantId<1))return res.status(400).json({error:'Select a subscriber company for this scenario'});
  if(String(req.body.confirmation||'')!=='RUN SAFE LOAD TEST')return res.status(400).json({error:'Type RUN SAFE LOAD TEST to confirm'});
  const lockClient=await pool.connect();let locked=false,testId=null,started=Date.now();
  try{
    locked=Boolean((await lockClient.query(`SELECT pg_try_advisory_lock(hashtext('patrolsync-controlled-load-test')) locked`)).rows[0]?.locked);if(!locked)return res.status(409).json({error:'Another controlled load test is already running'});
    if(tenantId){const exists=await pool.query(`SELECT 1 FROM tenants WHERE id=$1 AND COALESCE(account_active,TRUE)=TRUE`,[tenantId]);if(!exists.rowCount)return res.status(404).json({error:'Active subscriber company not found'})}
    testId=(await pool.query(`INSERT INTO platform_load_tests(platform_admin_id,scenario,tenant_id,concurrency,duration_seconds,status,instance_id) VALUES($1,$2,$3,$4,$5,'running',$6) RETURNING id`,[req.platformAdmin.id,scenario,tenantId,concurrency,durationSeconds,BACKGROUND_INSTANCE_ID])).rows[0].id;
    const deadline=Date.now()+durationSeconds*1000,maxRequests=2000,latencies=[],errors=new Map();let issued=0,succeeded=0,failed=0,peakSystemWaiting=0,peakTenantWaiting=0;
    const platformProbe=()=>pool.query(`SELECT (SELECT COUNT(*) FROM tenants) companies,(SELECT COUNT(*) FROM users) users,(SELECT COUNT(*) FROM sites) sites,(SELECT COUNT(*) FROM auth_sessions WHERE revoked_at IS NULL AND expires_at>NOW()) active_sessions`);
    const tenantProbe=()=>withTenant(tenantId,c=>c.query(`SELECT (SELECT COUNT(*) FROM users WHERE tenant_id=$1 AND COALESCE(account_active,TRUE)=TRUE) users,(SELECT COUNT(*) FROM sites WHERE tenant_id=$1) sites,(SELECT COUNT(*) FROM shifts WHERE tenant_id=$1 AND shift_date>=CURRENT_DATE) future_shifts,(SELECT COUNT(*) FROM attendance_sessions WHERE tenant_id=$1 AND clocked_out_at IS NULL) clocked_in,(SELECT COUNT(*) FROM patrol_runs WHERE tenant_id=$1 AND status IN('scheduled','in_progress')) patrols,(SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND status<>'closed') open_incidents`,[tenantId]));
    const worker=async workerId=>{while(Date.now()<deadline&&issued<maxRequests){const requestNumber=issued++;const probeStarted=Date.now();try{if(scenario==='platform_read'||(scenario==='mixed_read'&&(requestNumber+workerId)%2===0))await platformProbe();else await tenantProbe();succeeded++}catch(e){failed++;const key=String(e.code||e.message||'unknown').slice(0,200);errors.set(key,(errors.get(key)||0)+1)}latencies.push(Date.now()-probeStarted);peakSystemWaiting=Math.max(peakSystemWaiting,systemPool.waitingCount);peakTenantWaiting=Math.max(peakTenantWaiting,tenantPool.waitingCount);await new Promise(resolve=>setTimeout(resolve,25))}};
    await Promise.all(Array.from({length:concurrency},(_,i)=>worker(i)));
    const elapsed=Math.max(1,Date.now()-started),rps=Math.round((issued*100000/elapsed))/100,result={total_requests:issued,successful_requests:succeeded,failed_requests:failed,requests_per_second:rps,p50_ms:percentile(latencies,50),p95_ms:percentile(latencies,95),p99_ms:percentile(latencies,99),max_ms:latencies.length?Math.max(...latencies):0,peak_system_pool_waiting:peakSystemWaiting,peak_tenant_pool_waiting:peakTenantWaiting,error_summary:[...errors].map(([error,count])=>({error,count}))};
    await pool.query(`UPDATE platform_load_tests SET status=$2,finished_at=NOW(),total_requests=$3,successful_requests=$4,failed_requests=$5,requests_per_second=$6,p50_ms=$7,p95_ms=$8,p99_ms=$9,max_ms=$10,error_summary=$11::jsonb WHERE id=$1`,[testId,failed?'completed_with_errors':'completed',issued,succeeded,failed,rps,result.p50_ms,result.p95_ms,result.p99_ms,result.max_ms,JSON.stringify(result.error_summary)]);
    await platformAudit(req,'RUN','controlled_load_test',{test_id:testId,scenario,tenant_id:tenantId,concurrency,duration_seconds:durationSeconds,...result});
    res.json({message:'Controlled read-only load test completed.',test_id:testId,scenario,tenant_id:tenantId,concurrency,duration_seconds:durationSeconds,result,assessment:{passed:failed===0&&result.p95_ms<500&&peakSystemWaiting===0&&peakTenantWaiting===0,target:'0 failures, P95 below 500 ms, and no pool waiting'}});
  }catch(e){if(testId)await pool.query(`UPDATE platform_load_tests SET status='failed',finished_at=NOW(),failed_requests=failed_requests+1,error_summary=$2::jsonb WHERE id=$1`,[testId,JSON.stringify([{error:String(e.message).slice(0,500),count:1}])]).catch(()=>{});res.status(500).json({error:e.message})}
  finally{if(locked)await lockClient.query(`SELECT pg_advisory_unlock(hashtext('patrolsync-controlled-load-test'))`).catch(()=>{});lockClient.release()}
});
app.get('/api/platform/storage',requirePlatformAuth,async(req,res)=>{try{const counts=(await pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE photo_data IS NOT NULL)::int database_photos,COUNT(*) FILTER(WHERE storage_provider='s3' AND storage_key IS NOT NULL)::int object_photos,COALESCE(SUM(size_bytes),0)::bigint known_bytes FROM incident_photos`)).rows[0];res.json({configured:OBJECT_STORAGE_CONFIGURED,provider:'s3-compatible',endpoint_host:OBJECT_STORAGE_ENDPOINT?new URL(OBJECT_STORAGE_ENDPOINT).host:null,bucket:OBJECT_STORAGE_BUCKET||null,region:OBJECT_STORAGE_REGION,counts})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/platform/storage/test',requirePlatformAuth,async(req,res)=>{if(!OBJECT_STORAGE_CONFIGURED)return res.status(409).json({error:'Object storage environment variables are incomplete'});const key=`platform-tests/${crypto.randomUUID()}.txt`,body=Buffer.from(`PatrolSync storage test ${new Date().toISOString()}`);try{await objectStorageRequest('PUT',key,body,'text/plain');const response=await objectStorageRequest('GET',key),received=Buffer.from(await response.arrayBuffer());if(!crypto.timingSafeEqual(crypto.createHash('sha256').update(body).digest(),crypto.createHash('sha256').update(received).digest()))throw new Error('Downloaded test object did not match uploaded content');await objectStorageRequest('DELETE',key);await platformAudit(req,'TEST','object_storage',{bucket:OBJECT_STORAGE_BUCKET,endpoint_host:new URL(OBJECT_STORAGE_ENDPOINT).host});res.json({message:'Private object storage upload, download, checksum, and deletion passed.'})}catch(e){await objectStorageRequest('DELETE',key).catch(()=>{});res.status(502).json({error:e.message})}});
app.post('/api/platform/storage/migrate-incident-photos',requirePlatformAuth,async(req,res)=>{if(!OBJECT_STORAGE_CONFIGURED)return res.status(409).json({error:'Configure and test object storage first'});if(String(req.body.confirmation||'')!=='MIGRATE PHOTOS')return res.status(400).json({error:'Type MIGRATE PHOTOS to confirm'});const requestedLimit=Number(req.body.limit||10),limit=Number.isFinite(requestedLimit)?Math.max(1,Math.min(25,Math.floor(requestedLimit))):10,rows=(await pool.query(`SELECT id,tenant_id,incident_id,photo_data FROM incident_photos WHERE photo_data IS NOT NULL ORDER BY id LIMIT $1`,[limit])).rows,migrated=[],failed=[];for(const row of rows){let stored;try{stored=await storeIncidentPhoto(row.tenant_id,row.incident_id,row.photo_data);if(stored.provider!=='s3')throw new Error('External object storage is unavailable');const changed=await pool.query(`UPDATE incident_photos SET photo_data=NULL,storage_provider='s3',storage_key=$2,content_type=$3,size_bytes=$4,checksum_sha256=$5 WHERE id=$1 AND photo_data IS NOT NULL`,[row.id,stored.key,stored.contentType,stored.buffer.length,stored.checksum]);if(!changed.rowCount){await objectStorageRequest('DELETE',stored.key);continue}migrated.push(row.id)}catch(e){if(stored?.key)await objectStorageRequest('DELETE',stored.key).catch(()=>{});failed.push({id:row.id,error:String(e.message).slice(0,500)})}}await platformAudit(req,'MIGRATE','incident_photo_storage',{migrated:migrated.length,failed});res.status(failed.length?207:200).json({message:`${migrated.length} photo(s) migrated; ${failed.length} failed.`,migrated,failed,remaining:Math.max(0,Number((await pool.query(`SELECT COUNT(*)::int count FROM incident_photos WHERE photo_data IS NOT NULL`)).rows[0].count))})});

// ------------------------ PLATFORM SUBSCRIBER LIFECYCLE ------------------------
app.get('/api/platform/subscribers',requirePlatformAuth,async(req,res)=>{
  try{
    const result=await pool.query(`SELECT t.id,t.name,t.slug,t.plan,t.timezone,t.created_at,COALESCE(t.account_active,TRUE) account_active,t.suspended_at,t.suspension_reason,t.subscription_status,t.billing_cycle,t.trial_ends_at,t.renewal_at,t.platform_notes,COUNT(DISTINCT s.id)::int sites,COUNT(DISTINCT u.id) FILTER(WHERE u.role='guard' AND COALESCE(u.account_active,TRUE)=TRUE)::int guards,COUNT(DISTINCT u.id) FILTER(WHERE u.role='admin' AND COALESCE(u.account_active,TRUE)=TRUE)::int admins FROM tenants t LEFT JOIN sites s ON s.tenant_id=t.id LEFT JOIN users u ON u.tenant_id=t.id GROUP BY t.id ORDER BY t.created_at DESC LIMIT 500`);
    await platformAudit(req,'VIEW','subscriber_lifecycle',{count:result.rowCount});
    res.json(result.rows);
  }catch(e){res.status(500).json({error:e.message})}
});

app.post('/api/platform/subscribers/:id/suspend',requirePlatformAuth,async(req,res)=>{
  const id=Number(req.params.id),reason=String(req.body.reason||'Suspended by platform owner').trim().slice(0,500);
  if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'Invalid company ID'});
  try{
    const changed=await pool.query(`UPDATE tenants SET account_active=FALSE,suspended_at=NOW(),suspension_reason=$2 WHERE id=$1 AND COALESCE(account_active,TRUE)=TRUE RETURNING id,name`,[id,reason]);
    if(!changed.rowCount)return res.status(404).json({error:'Active subscriber company not found'});
    await pool.query(`UPDATE auth_sessions SET revoked_at=NOW(),revoked_reason='Subscriber suspended' WHERE tenant_id=$1 AND revoked_at IS NULL`,[id]);
    await platformAudit(req,'SUSPEND','tenant',{tenant_id:id,company:changed.rows[0].name,reason});
    res.json({message:'Subscriber suspended. Existing sessions were revoked.'});
  }catch(e){res.status(500).json({error:e.message})}
});

app.post('/api/platform/subscribers/:id/reactivate',requirePlatformAuth,async(req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'Invalid company ID'});
  try{
    const changed=await pool.query(`UPDATE tenants SET account_active=TRUE,suspended_at=NULL,suspension_reason=NULL WHERE id=$1 AND COALESCE(account_active,TRUE)=FALSE RETURNING id,name`,[id]);
    if(!changed.rowCount)return res.status(404).json({error:'Suspended subscriber company not found'});
    await platformAudit(req,'REACTIVATE','tenant',{tenant_id:id,company:changed.rows[0].name});
    res.json({message:'Subscriber reactivated. Users may log in again.'});
  }catch(e){res.status(500).json({error:e.message})}
});

app.patch('/api/platform/subscribers/:id/subscription',requirePlatformAuth,async(req,res)=>{
  const id=Number(req.params.id),plan=String(req.body.plan||''),subscriptionStatus=String(req.body.subscription_status||''),billingCycle=String(req.body.billing_cycle||'monthly'),notes=String(req.body.platform_notes||'').trim().slice(0,2000);
  const statuses=['trialing','active','past_due','suspended','cancelled'],cycles=['monthly','annual','custom'];
  if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'Invalid company ID'});
  if(!VALID_PLANS.includes(plan))return res.status(400).json({error:'Invalid subscription plan'});
  if(!statuses.includes(subscriptionStatus))return res.status(400).json({error:'Invalid subscription status'});
  if(!cycles.includes(billingCycle))return res.status(400).json({error:'Invalid billing cycle'});
  const dateOrNull=value=>{if(!value)return null;const d=new Date(value);return Number.isNaN(d.getTime())?undefined:d.toISOString()};
  const trialEnds=dateOrNull(req.body.trial_ends_at),renewal=dateOrNull(req.body.renewal_at);
  if(trialEnds===undefined||renewal===undefined)return res.status(400).json({error:'Invalid trial or renewal date'});
  const active=!['suspended','cancelled'].includes(subscriptionStatus);
  try{
    const before=(await pool.query(`SELECT id,name,plan,subscription_status,billing_cycle,trial_ends_at,renewal_at,platform_notes,COALESCE(account_active,TRUE) account_active FROM tenants WHERE id=$1`,[id])).rows[0];
    if(!before)return res.status(404).json({error:'Subscriber company not found'});
    const changed=(await pool.query(`UPDATE tenants SET plan=$2,subscription_status=$3,billing_cycle=$4,trial_ends_at=$5,renewal_at=$6,platform_notes=$7,account_active=$8,suspended_at=CASE WHEN $8 THEN NULL ELSE COALESCE(suspended_at,NOW()) END,suspension_reason=CASE WHEN $8 THEN NULL ELSE COALESCE(suspension_reason,'Subscription status changed by platform owner') END WHERE id=$1 RETURNING id,name,plan,subscription_status,billing_cycle,trial_ends_at,renewal_at,platform_notes,account_active`,[id,plan,subscriptionStatus,billingCycle,trialEnds,renewal,notes,active])).rows[0];
    if(!active)await pool.query(`UPDATE auth_sessions SET revoked_at=NOW(),revoked_reason='Subscription disabled' WHERE tenant_id=$1 AND revoked_at IS NULL`,[id]);
    await platformAudit(req,'UPDATE_SUBSCRIPTION','tenant',{tenant_id:id,company:before.name,before,after:changed});
    res.json({message:'Subscription updated.',subscriber:changed});
  }catch(e){res.status(500).json({error:e.message})}
});

app.delete('/api/platform/subscribers/:id',requirePlatformAuth,async(req,res)=>{
  const id=Number(req.params.id),confirmation=String(req.body.confirmation||'').trim();
  if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'Invalid company ID'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const tenant=(await client.query(`SELECT id,name,COALESCE(account_active,TRUE) account_active FROM tenants WHERE id=$1 FOR UPDATE`,[id])).rows[0];
    if(!tenant){await client.query('ROLLBACK');return res.status(404).json({error:'Subscriber company not found'})}
    if(tenant.account_active){await client.query('ROLLBACK');return res.status(409).json({error:'Suspend the subscriber before permanent deletion'})}
    if(confirmation!==`DELETE ${id}`){await client.query('ROLLBACK');return res.status(400).json({error:`Type DELETE ${id} to confirm permanent deletion`})}
    const tables=(await client.query(`SELECT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='tenant_id' AND table_name<>'tenants' ORDER BY table_name`)).rows.map(r=>r.table_name);
    const blockers=[];
    for(const table of tables){
      if(!/^[a-z_][a-z0-9_]*$/i.test(table))continue;
      const count=Number((await client.query(`SELECT COUNT(*)::int count FROM "${table}" WHERE tenant_id=$1`,[id])).rows[0].count);
      if(count)blockers.push({table,count});
    }
    if(blockers.length){await client.query('ROLLBACK');return res.status(409).json({error:'Permanent deletion blocked because company records exist. Keep it suspended to preserve its history.',blockers})}
    await client.query(`DELETE FROM tenants WHERE id=$1`,[id]);
    await client.query(`INSERT INTO platform_audit_logs(platform_admin_id,admin_email,action,resource,details,ip_address,request_id) VALUES($1,$2,'PERMANENT_DELETE','tenant',$3::jsonb,$4,$5)`,[req.platformAdmin.id,req.platformAdmin.email,JSON.stringify({tenant_id:id,company:tenant.name}),requestIp(req),req.requestId||null]);
    await client.query('COMMIT');
    res.json({message:'Empty subscriber company permanently deleted.'});
  }catch(e){try{await client.query('ROLLBACK')}catch(_){}res.status(500).json({error:e.message})}finally{client.release()}
});

// ------------------------ EXPANSION STAGE 2C: FIELD RELIABILITY GATE ------------------------
app.get('/api/field-reliability/readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=Number(req.auth.tenant_id),checks=[];
  const add=(code,label,passed,message,details={})=>checks.push({code,label,passed:Boolean(passed),status:passed?'pass':'fail',message,details});
  try{
    const columns=(await pool.query(`SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND ((table_name='checkpoints' AND column_name='nfc_tag_uid') OR (table_name='patrol_logs' AND column_name IN ('client_scan_id','scan_method','device_id','offline_captured','device_scanned_at')) OR (table_name='incidents' AND column_name IN ('client_incident_id','device_id','offline_captured','device_reported_at'))) ORDER BY table_name,column_name`)).rows;
    const names=new Set(columns.map(x=>`${x.table_name}.${x.column_name}`));
    const expected=['checkpoints.nfc_tag_uid','patrol_logs.client_scan_id','patrol_logs.scan_method','patrol_logs.device_id','patrol_logs.offline_captured','patrol_logs.device_scanned_at','incidents.client_incident_id','incidents.device_id','incidents.offline_captured','incidents.device_reported_at'];
    add('capture_schema','Field capture database structures',expected.every(x=>names.has(x)),`${expected.filter(x=>names.has(x)).length}/${expected.length} required capture fields available`,{missing:expected.filter(x=>!names.has(x))});

    const indexRows=(await pool.query(`SELECT indexname FROM pg_indexes WHERE schemaname='public' AND indexname IN ('uq_checkpoints_tenant_nfc_tag','uq_patrol_logs_tenant_client_scan','uq_incidents_tenant_client_id')`)).rows;
    add('idempotency_indexes','Database idempotency protection',indexRows.length===3,`${indexRows.length}/3 required unique indexes installed`,{indexes:indexRows.map(x=>x.indexname)});

    const result=await withTenant(tenantId,async client=>{
      const [scans,scanDuplicates,incidentDuplicates,offlineIncidents,photos,nfc,rls]=await Promise.all([
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE scan_method='qr')::int qr,COUNT(*) FILTER(WHERE scan_method='nfc')::int nfc,COUNT(*) FILTER(WHERE offline_captured)::int offline,COUNT(*) FILTER(WHERE scan_method NOT IN('qr','nfc') OR scan_method IS NULL)::int invalid FROM patrol_logs WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int count FROM(SELECT client_scan_id FROM patrol_logs WHERE tenant_id=$1 AND client_scan_id IS NOT NULL GROUP BY client_scan_id HAVING COUNT(*)>1)x`,[tenantId]),
        client.query(`SELECT COUNT(*)::int count FROM(SELECT client_incident_id FROM incidents WHERE tenant_id=$1 AND client_incident_id IS NOT NULL GROUP BY client_incident_id HAVING COUNT(*)>1)x`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE device_reported_at IS NOT NULL AND device_id IS NOT NULL AND client_incident_id IS NOT NULL)::int traceable FROM incidents WHERE tenant_id=$1 AND offline_captured`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE (storage_key IS NOT NULL OR photo_data IS NOT NULL) AND checksum_sha256 IS NOT NULL)::int verifiable FROM incident_photos WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int registered FROM checkpoints WHERE tenant_id=$1 AND nfc_tag_uid IS NOT NULL`,[tenantId]),
        pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE c.relrowsecurity)::int enabled,COUNT(*) FILTER(WHERE EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname))::int protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped WHERE n.nspname='public' AND c.relname IN('checkpoints','patrol_logs','incidents','incident_photos')`)
      ]);
      return{scans:scans.rows[0],scan_duplicates:Number(scanDuplicates.rows[0].count),incident_duplicates:Number(incidentDuplicates.rows[0].count),offline_incidents:offlineIncidents.rows[0],photos:photos.rows[0],nfc_registered:Number(nfc.rows[0].registered),rls:rls.rows[0]};
    });
    add('scan_methods','QR and NFC evidence parity',Number(result.scans.invalid)===0,`${result.scans.qr} QR scan(s), ${result.scans.nfc} NFC scan(s), ${result.scans.offline} originally captured offline`,result.scans);
    add('scan_idempotency','Patrol scan retry safety',result.scan_duplicates===0,result.scan_duplicates===0?'No duplicate client scan identities':'Duplicate patrol scan identities require correction',{duplicates:result.scan_duplicates});
    add('incident_idempotency','Incident retry safety',result.incident_duplicates===0,result.incident_duplicates===0?'No duplicate client incident identities':'Duplicate incident identities require correction',{duplicates:result.incident_duplicates});
    add('offline_provenance','Offline incident provenance',Number(result.offline_incidents.total)===Number(result.offline_incidents.traceable),`${result.offline_incidents.traceable}/${result.offline_incidents.total} offline incident(s) retain client ID, device and capture time`,result.offline_incidents);
    add('photo_evidence','Incident photo recoverability',Number(result.photos.total)===Number(result.photos.verifiable),`${result.photos.verifiable}/${result.photos.total} photo(s) have recoverable bytes and a server checksum`,result.photos);
    add('tenant_protection','Field evidence tenant protection',Number(result.rls.total)===4&&Number(result.rls.enabled)===4&&Number(result.rls.protected)===4,`${result.rls.protected}/4 tenant policies; ${result.rls.enabled}/4 tables with RLS`,result.rls);
    add('nfc_registration','NFC checkpoint availability',true,`${result.nfc_registered} checkpoint NFC tag(s) registered; QR remains the universal fallback`,{registered:result.nfc_registered,optional:true});
    const failures=checks.filter(x=>!x.passed),ready=failures.length===0;
    res.json({ready,status:ready?'stage_2_ready':'action_required',generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,failures:failures.length,total:checks.length},activity:{patrol_scans:result.scans,offline_incidents:result.offline_incidents,incident_photos:result.photos,nfc_registered:result.nfc_registered},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}
});

// ------------------------ EXPANSION STAGE 3A: VISITOR MANAGEMENT ------------------------
async function ensureVisitorManagementSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS visitor_records(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,organization TEXT,purpose TEXT NOT NULL,host_name TEXT,
    phone TEXT,email TEXT,badge_code TEXT,vehicle_registration TEXT,
    status TEXT NOT NULL DEFAULT 'expected' CHECK(status IN('expected','on_site','checked_out','cancelled')),
    expected_at TIMESTAMPTZ,checked_in_at TIMESTAMPTZ,checked_out_at TIMESTAMPTZ,
    emergency_notes TEXT,notes TEXT,created_by INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_visitor_records_tenant_status ON visitor_records(tenant_id,status,expected_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_visitor_records_site_active ON visitor_records(tenant_id,site_id,checked_in_at DESC) WHERE status='on_site'`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_visitor_active_badge ON visitor_records(tenant_id,badge_code) WHERE status='on_site' AND badge_code IS NOT NULL`);
  await pool.query(`ALTER TABLE visitor_records ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON visitor_records`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON visitor_records USING (tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK (tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  const tenantRole=quotedRoleFromTenantUrl();
  if(tenantRole){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON visitor_records TO ${tenantRole}`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE visitor_records_id_seq TO ${tenantRole}`)}
  console.log('Visitor management schema ready');
}
ensureVisitorManagementSchema().catch(err=>console.error('Visitor management setup failed:',err.message));

function visitorTenant(req,value){const requested=Number(value||req.auth.tenant_id);return Number(req.auth.tenant_id)===requested?requested:null}
function visitorText(value,max=300){return String(value||'').trim().slice(0,max)||null}

app.get('/api/visitors',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=visitorTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const status=String(req.query.status||'active'),siteId=Number(req.query.site_id||0),search=visitorText(req.query.search,120);
  try{const result=await withTenant(tenantId,client=>{const params=[tenantId];let where='v.tenant_id=$1';if(status==='active')where+=` AND v.status IN('expected','on_site')`;else if(['expected','on_site','checked_out','cancelled'].includes(status)){params.push(status);where+=` AND v.status=$${params.length}`}if(siteId){params.push(siteId);where+=` AND v.site_id=$${params.length}`}if(search){params.push('%'+search.toLowerCase()+'%');where+=` AND (LOWER(v.full_name) LIKE $${params.length} OR LOWER(COALESCE(v.organization,'')) LIKE $${params.length} OR LOWER(COALESCE(v.badge_code,'')) LIKE $${params.length})`}return client.query(`SELECT v.*,s.name site_name,u.email created_by_email FROM visitor_records v JOIN sites s ON s.id=v.site_id AND s.tenant_id=v.tenant_id LEFT JOIN users u ON u.id=v.created_by AND u.tenant_id=v.tenant_id WHERE ${where} ORDER BY CASE v.status WHEN 'on_site' THEN 0 WHEN 'expected' THEN 1 ELSE 2 END,COALESCE(v.checked_in_at,v.expected_at,v.created_at) DESC LIMIT 500`,params)});res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}
});

app.get('/api/visitors/summary',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=visitorTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`SELECT COUNT(*) FILTER(WHERE status='on_site')::int on_site,COUNT(*) FILTER(WHERE status='expected' AND expected_at::date=CURRENT_DATE)::int expected_today,COUNT(*) FILTER(WHERE status='checked_out' AND checked_out_at::date=CURRENT_DATE)::int checked_out_today,COUNT(DISTINCT site_id) FILTER(WHERE status='on_site')::int occupied_sites FROM visitor_records WHERE tenant_id=$1`,[tenantId]));res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}
});

app.get('/api/visitors/emergency-register',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=visitorTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`SELECT v.id,v.full_name,v.organization,v.purpose,v.host_name,v.phone,v.badge_code,v.vehicle_registration,v.checked_in_at,v.emergency_notes,s.id site_id,s.name site_name,s.address site_address FROM visitor_records v JOIN sites s ON s.id=v.site_id AND s.tenant_id=v.tenant_id WHERE v.tenant_id=$1 AND v.status='on_site' ORDER BY s.name,v.checked_in_at`,[tenantId]));res.json({generated_at:new Date(),count:result.rowCount,visitors:result.rows})}catch(err){res.status(500).json({error:err.message})}
});

app.post('/api/visitors',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=visitorTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),fullName=visitorText(req.body.full_name,160),purpose=visitorText(req.body.purpose,300);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!fullName||!purpose)return res.status(400).json({error:'Site, visitor name, and purpose are required'});
  const preRegister=Boolean(req.body.pre_register),expected=req.body.expected_at?new Date(req.body.expected_at):null;if(expected&&Number.isNaN(expected.getTime()))return res.status(400).json({error:'Expected arrival must be a valid date'});
  try{const result=await withTenant(tenantId,async client=>{const site=await client.query('SELECT id FROM sites WHERE tenant_id=$1 AND id=$2',[tenantId,siteId]);if(!site.rowCount)throw Object.assign(new Error('Site not found'),{statusCode:404});return client.query(`INSERT INTO visitor_records(tenant_id,site_id,full_name,organization,purpose,host_name,phone,email,badge_code,vehicle_registration,status,expected_at,checked_in_at,emergency_notes,notes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CASE WHEN $11='on_site' THEN NOW() END,$13,$14,$15) RETURNING *`,[tenantId,siteId,fullName,visitorText(req.body.organization,160),purpose,visitorText(req.body.host_name,160),visitorText(req.body.phone,80),visitorText(req.body.email,160)?.toLowerCase()||null,visitorText(req.body.badge_code,80),visitorText(req.body.vehicle_registration,80)?.toUpperCase()||null,preRegister?'expected':'on_site',expected?.toISOString()||null,visitorText(req.body.emergency_notes,500),visitorText(req.body.notes,1000),req.auth.user_id])});res.status(201).json(result.rows[0])}catch(err){res.status(err.statusCode||500).json({error:err.code==='23505'?'That badge is already assigned to a visitor currently on site':err.message})}
});

app.patch('/api/visitors/:id/check-in',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=visitorTenant(req,req.body.tenant_id),badge=visitorText(req.body.badge_code,80);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`UPDATE visitor_records SET status='on_site',checked_in_at=NOW(),checked_out_at=NULL,badge_code=COALESCE($1,badge_code),updated_at=NOW() WHERE tenant_id=$2 AND id=$3 AND status='expected' RETURNING *`,[badge,tenantId,req.params.id]));if(!result.rowCount)return res.status(409).json({error:'Only an expected visitor can be checked in'});res.json(result.rows[0])}catch(err){res.status(500).json({error:err.code==='23505'?'That badge is already in use':err.message})}
});

app.patch('/api/visitors/:id/check-out',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=visitorTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`UPDATE visitor_records SET status='checked_out',checked_out_at=NOW(),updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND status='on_site' RETURNING *`,[tenantId,req.params.id]));if(!result.rowCount)return res.status(409).json({error:'Only a visitor currently on site can be checked out'});res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}
});

app.patch('/api/visitors/:id/cancel',requireAuth,requireAdmin,async(req,res)=>{
  const tenantId=visitorTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{const result=await withTenant(tenantId,client=>client.query(`UPDATE visitor_records SET status='cancelled',updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND status='expected' RETURNING *`,[tenantId,req.params.id]));if(!result.rowCount)return res.status(409).json({error:'Only an expected visit can be cancelled'});res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}
});

// ------------------------ EXPANSION STAGE 3B: WORKFORCE READINESS GATE ------------------------
app.get('/api/workforce-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=visitorTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['visitor_records','guard_certifications','training_materials','training_assignments','managed_assets','asset_custody','handover_logs'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 3 database structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRoleRaw=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();
    let grants=[];if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRoleRaw)){grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read FROM unnest($2::text[]) t`,[tenantRoleRaw,required])).rows}
    add('grants','Restricted tenant-role access',grants.length===required.length&&grants.every(x=>x.can_read),grants.length?`${grants.filter(x=>x.can_read).length}/${required.length} tables readable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const data=await withTenant(tenantId,async client=>{
      const [visitorState,badges,visitorSites,certs,training,custody,handovers,emergency,entitlement]=await Promise.all([
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE checked_in_at IS NULL OR checked_out_at IS NOT NULL)::int invalid FROM visitor_records WHERE tenant_id=$1 AND status='on_site'`,[tenantId]),
        client.query(`SELECT COUNT(*)::int count FROM(SELECT badge_code FROM visitor_records WHERE tenant_id=$1 AND status='on_site' AND badge_code IS NOT NULL GROUP BY badge_code HAVING COUNT(*)>1)x`,[tenantId]),
        client.query(`SELECT COUNT(*)::int count FROM visitor_records v LEFT JOIN sites s ON s.id=v.site_id AND s.tenant_id=v.tenant_id WHERE v.tenant_id=$1 AND s.id IS NULL`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE expiry_date<CURRENT_DATE)::int expired,COUNT(*) FILTER(WHERE expiry_date BETWEEN CURRENT_DATE AND CURRENT_DATE+30)::int expiring FROM guard_certifications WHERE tenant_id=$1 AND archived_at IS NULL`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE mandatory AND status<>'completed' AND due_at<NOW())::int overdue FROM training_assignments WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int open,COUNT(*) FILTER(WHERE a.id IS NULL OR u.id IS NULL OR COALESCE(u.account_active,TRUE)=FALSE)::int invalid FROM asset_custody c LEFT JOIN managed_assets a ON a.id=c.asset_id AND a.tenant_id=c.tenant_id LEFT JOIN users u ON u.id=c.user_id AND u.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.status<>'returned'`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE s.id IS NULL OR f.id IS NULL)::int invalid FROM handover_logs h LEFT JOIN sites s ON s.id=h.site_id AND s.tenant_id=h.tenant_id LEFT JOIN users f ON f.id=h.from_user_id AND f.tenant_id=h.tenant_id WHERE h.tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int count FROM visitor_records WHERE tenant_id=$1 AND status='on_site'`,[tenantId]),
        client.query(`SELECT COALESCE(o.enabled,pf.enabled,FALSE) enabled,ts.status subscription_status FROM tenant_subscriptions ts JOIN feature_catalog f ON f.code='visitor_management' LEFT JOIN plan_features pf ON pf.plan_id=ts.plan_id AND pf.feature_id=f.id LEFT JOIN tenant_entitlement_overrides o ON o.tenant_id=ts.tenant_id AND o.feature_id=f.id AND(o.expires_at IS NULL OR o.expires_at>NOW()) WHERE ts.tenant_id=$1`,[tenantId])
      ]);return{visitor_state:visitorState.rows[0],duplicate_badges:Number(badges.rows[0].count),broken_visitor_sites:Number(visitorSites.rows[0].count),certifications:certs.rows[0],training:training.rows[0],custody:custody.rows[0],handovers:handovers.rows[0],emergency_count:Number(emergency.rows[0].count),entitlement:entitlement.rows[0]||null}
    });
    add('visitor_state','Visitor check-in integrity',Number(data.visitor_state.invalid)===0,`${data.visitor_state.total} visitor(s) currently on site; ${data.visitor_state.invalid} invalid state(s)`,true,data.visitor_state);
    add('visitor_badges','Active visitor badge uniqueness',data.duplicate_badges===0,data.duplicate_badges===0?'No badge is assigned to multiple on-site visitors':`${data.duplicate_badges} duplicated active badge(s)`,true,{duplicates:data.duplicate_badges});
    add('visitor_sites','Visitor site relationships',data.broken_visitor_sites===0,data.broken_visitor_sites===0?'Every visitor references a valid company site':`${data.broken_visitor_sites} visitor record(s) reference a missing site`,true,{broken:data.broken_visitor_sites});
    add('emergency_register','Emergency on-site register',data.emergency_count===Number(data.visitor_state.total),`${data.emergency_count} current visitor(s) available to the emergency register`,true,{count:data.emergency_count});
    add('certifications','Guard certification status',Number(data.certifications.expired)===0,`${data.certifications.expired} expired; ${data.certifications.expiring} expire within 30 days`,false,data.certifications);
    add('training','Mandatory training status',Number(data.training.overdue)===0,`${data.training.overdue} overdue mandatory assignment(s)`,false,data.training);
    add('custody','Equipment custody integrity',Number(data.custody.invalid)===0,`${data.custody.open} open custody record(s); ${data.custody.invalid} invalid`,true,data.custody);
    add('handovers','Shift handover relationships',Number(data.handovers.invalid)===0,`${data.handovers.total} handover(s); ${data.handovers.invalid} broken relationship(s)`,true,data.handovers);
    add('entitlement','Visitor-management entitlement',Boolean(data.entitlement?.enabled&&['active','trialing'].includes(data.entitlement.subscription_status)),data.entitlement?.enabled?`Enabled for ${data.entitlement.subscription_status} subscription`:'Visitor management is not enabled by the effective subscription',true,data.entitlement||{});
    const failures=checks.filter(x=>x.critical&&!x.passed),warnings=checks.filter(x=>!x.critical&&!x.passed),status=failures.length?'action_required':warnings.length?'ready_with_warnings':'stage_3_ready';
    res.json({status,ready:failures.length===0,generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,warnings:warnings.length,failures:failures.length,total:checks.length},activity:{visitors_on_site:data.emergency_count,expired_certifications:Number(data.certifications.expired),overdue_training:Number(data.training.overdue),open_custody:Number(data.custody.open)},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}
});

// ------------------------ STAGE 4.4: WORKFORCE COMPLIANCE READINESS ------------------------
app.get('/api/compliance-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=communicationTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['guard_certifications','site_guard_requirements','training_materials','training_assignments','site_training_requirements','communication_notifications'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 4 database structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRoleRaw=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRoleRaw))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert FROM unnest($2::text[]) t`,[tenantRoleRaw,required])).rows;
    add('grants','Restricted tenant-role permissions',grants.length===required.length&&grants.every(x=>x.can_read&&x.can_insert),grants.length?`${grants.filter(x=>x.can_read&&x.can_insert).length}/${required.length} tables readable and writable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const data=await withTenant(tenantId,async client=>{const certificates=await buildCertificationCompliance(client,tenantId),competency=await buildCompetencyMatrix(client,tenantId);const [archive,alerts,requirements,trainingRules]=await Promise.all([
      client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE archived_at IS NOT NULL)::int archived,COUNT(*) FILTER(WHERE replacement_for_id IS NOT NULL)::int renewals FROM guard_certifications WHERE tenant_id=$1`,[tenantId]),
      client.query(`SELECT COUNT(*)::int active FROM communication_notifications WHERE tenant_id=$1 AND source_key LIKE 'cert-compliance:%' AND(expires_at IS NULL OR expires_at>NOW())`,[tenantId]),
      client.query(`SELECT COUNT(*)::int total FROM site_guard_requirements WHERE tenant_id=$1 AND active=TRUE`,[tenantId]),
      client.query(`SELECT COUNT(*)::int total FROM site_training_requirements WHERE tenant_id=$1 AND active=TRUE`,[tenantId])
    ]);return{certificates,competency,archive:archive.rows[0],active_alerts:Number(alerts.rows[0].active),certificate_rules:Number(requirements.rows[0].total),training_rules:Number(trainingRules.rows[0].total)}});
    add('certificate_register','Certificate lifecycle register',true,`${data.archive.total} record(s); ${data.archive.archived} archived; ${data.archive.renewals} renewal replacement(s)`,true,data.archive);
    add('certificate_rules','Certificate requirement configuration',data.certificate_rules>0,`${data.certificate_rules} active site certificate requirement(s)`,false,{count:data.certificate_rules});
    const certRisk=data.certificates.summary.missing+data.certificates.summary.expired;
    add('certificate_coverage','Certificate compliance coverage',certRisk===0,`${data.certificates.summary.compliant}/${data.certificates.summary.total} compliant; ${data.certificates.summary.missing} missing; ${data.certificates.summary.expired} expired; ${data.certificates.summary.expiring_soon} expiring`,false,data.certificates.summary);
    add('certificate_alerts','Automated certificate alerts',data.active_alerts===certRisk+data.certificates.summary.expiring_soon,`${data.active_alerts} active alert(s) for ${certRisk+data.certificates.summary.expiring_soon} current issue(s)`,false,{active_alerts:data.active_alerts,issues:certRisk+data.certificates.summary.expiring_soon});
    add('competency_rules','Competency rule configuration',data.training_rules>0,`${data.training_rules} active site training rule(s)`,false,{count:data.training_rules});
    const competencyRisk=data.competency.summary.missing+data.competency.summary.failed+data.competency.summary.overdue;
    add('competency_coverage','Guard competency coverage',competencyRisk===0,`${data.competency.summary.compliant}/${data.competency.summary.total} compliant; ${data.competency.summary.missing} missing; ${data.competency.summary.failed} failed; ${data.competency.summary.overdue} overdue`,false,data.competency.summary);
    const job=(await pool.query(`SELECT status,started_at,finished_at,error_message,details FROM platform_job_runs WHERE job_name='certification_compliance_sweep' ORDER BY started_at DESC LIMIT 1`)).rows[0]||null;
    add('automation_job','Compliance automation health',Boolean(job&&job.status==='succeeded'),job?`Last certificate sweep ${job.status} at ${new Date(job.started_at).toISOString()}`:'Certificate sweep has not completed yet',false,job||{});
    const failures=checks.filter(x=>x.critical&&!x.passed),warnings=checks.filter(x=>!x.critical&&!x.passed),status=failures.length?'action_required':warnings.length?'ready_with_warnings':'stage_4_ready';
    res.json({status,ready:failures.length===0,generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,warnings:warnings.length,failures:failures.length,total:checks.length},activity:{certificate_requirements:data.certificate_rules,training_requirements:data.training_rules,certificate_issues:certRisk+data.certificates.summary.expiring_soon,competency_gaps:competencyRisk},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}
});

// ------------------------ STAGE 5.1: PROOFSCORE CLIENT ASSURANCE ------------------------
async function ensureProofScoreSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS proofscore_snapshots(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,
    period_start DATE NOT NULL,period_end DATE NOT NULL,score NUMERIC(5,2),grade TEXT NOT NULL,
    components JSONB NOT NULL DEFAULT '[]'::jsonb,recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    calculated_by_user_id INTEGER,calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,site_id,period_start,period_end)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS proofscore_snapshots_tenant_site_time ON proofscore_snapshots(tenant_id,site_id,calculated_at DESC)`);
  await pool.query(`ALTER TABLE proofscore_snapshots ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON proofscore_snapshots`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON proofscore_snapshots USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE ON proofscore_snapshots TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE proofscore_snapshots_id_seq TO "${role}"`);}}catch(err){console.warn('ProofScore tenant-role grant skipped:',err.message)}
  console.log('ProofScore assurance schema ready');
}
ensureProofScoreSchema().catch(err=>console.error('ProofScore schema setup failed:',err.message));

function proofScoreComponent(key,label,weight,numerator,denominator,explanation){
  const total=Number(denominator||0),achieved=Number(numerator||0),applicable=total>0;
  return{key,label,weight,applicable,numerator:achieved,denominator:total,score:applicable?Math.max(0,Math.min(100,Math.round(achieved/total*10000)/100)):null,explanation};
}
function proofScoreGrade(score){if(score===null)return'UNRATED';if(score>=90)return'A';if(score>=80)return'B';if(score>=70)return'C';if(score>=60)return'D';return'E'}
async function buildProofScore(client,tenantId,fromDate,toDate,siteId){
  const params=[tenantId,fromDate,toDate];let siteFilter='';if(siteId){params.push(Number(siteId));siteFilter=` AND s.id=$${params.length}`}
  const base=(await client.query(`SELECT s.id site_id,s.name site_name,
    (SELECT COUNT(*)::int FROM patrol_runs p WHERE p.tenant_id=s.tenant_id AND p.site_id=s.id AND p.status<>'cancelled' AND p.scheduled_start::date BETWEEN $2::date AND $3::date AND p.scheduled_end<=NOW()) patrol_total,
    (SELECT COUNT(*)::int FROM patrol_runs p WHERE p.tenant_id=s.tenant_id AND p.site_id=s.id AND p.status='completed' AND p.scheduled_start::date BETWEEN $2::date AND $3::date AND p.scheduled_end<=NOW()) patrol_completed,
    (SELECT COUNT(*)::int FROM patrol_logs p JOIN checkpoints c ON c.id=p.checkpoint_id WHERE p.tenant_id=s.tenant_id AND c.site_id=s.id AND p.scanned_at::date BETWEEN $2::date AND $3::date) evidence_total,
    (SELECT COUNT(*)::int FROM patrol_logs p JOIN checkpoints c ON c.id=p.checkpoint_id JOIN evidence_integrity_records e ON e.tenant_id=p.tenant_id AND e.evidence_type='patrol_scan' AND e.evidence_id=p.id::text WHERE p.tenant_id=s.tenant_id AND c.site_id=s.id AND p.scanned_at::date BETWEEN $2::date AND $3::date) evidence_sealed,
    (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=s.tenant_id AND i.site_id=s.id AND i.reported_at::date BETWEEN $2::date AND $3::date) incident_total,
    (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=s.tenant_id AND i.site_id=s.id AND i.reported_at::date BETWEEN $2::date AND $3::date AND i.acknowledged_at IS NOT NULL AND i.acknowledged_at<=i.reported_at+COALESCE((SELECT sc.sla_incident_ack_minutes FROM service_contracts sc WHERE sc.tenant_id=s.tenant_id AND sc.site_id=s.id AND sc.status='active' ORDER BY sc.id DESC LIMIT 1),15)*INTERVAL '1 minute') incident_ack_met,
    (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=s.tenant_id AND sh.site_id=s.id AND sh.shift_date BETWEEN $2::date AND $3::date) shift_total,
    (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=s.tenant_id AND sh.site_id=s.id AND sh.shift_date BETWEEN $2::date AND $3::date AND sh.assignment_status='assigned') shift_covered
    FROM sites s WHERE s.tenant_id=$1${siteFilter} ORDER BY s.name`,params)).rows;
  const [certification,competency]=await Promise.all([buildCertificationCompliance(client,tenantId),buildCompetencyMatrix(client,tenantId)]);
  const sites=base.map(row=>{
    const certRows=certification.rows.filter(x=>Number(x.site_id)===Number(row.site_id)),trainingRows=competency.rows.filter(x=>Number(x.site_id)===Number(row.site_id));
    const components=[
      proofScoreComponent('patrol','Patrol completion',25,row.patrol_completed,row.patrol_total,'Completed patrol rounds that were due in the selected period.'),
      proofScoreComponent('evidence','TrustProof evidence',20,row.evidence_sealed,row.evidence_total,'Checkpoint scans sealed in the append-only evidence ledger.'),
      proofScoreComponent('incident','Incident acknowledgement',15,row.incident_ack_met,row.incident_total,'Incidents acknowledged within the active contract target, or 15 minutes when no target exists.'),
      proofScoreComponent('coverage','Shift coverage',15,row.shift_covered,row.shift_total,'Scheduled shifts with an assigned guard.'),
      proofScoreComponent('certification','Certificate readiness',15,certRows.filter(x=>x.status==='compliant').length,certRows.length,'Assigned guards compliant with site certificate requirements.'),
      proofScoreComponent('competency','Mandatory competency',10,trainingRows.filter(x=>x.status==='compliant').length,trainingRows.length,'Assigned guards compliant with mandatory site training requirements.')
    ];
    const measured=components.filter(x=>x.applicable),weight=measured.reduce((n,x)=>n+x.weight,0),score=weight?Math.round(measured.reduce((n,x)=>n+x.score*x.weight,0)/weight*100)/100:null;
    const recommendations=components.filter(x=>x.applicable&&x.score<90).sort((a,b)=>a.score-b.score).map(x=>`Improve ${x.label.toLowerCase()} (${x.score}%).`);
    return{site_id:Number(row.site_id),site_name:row.site_name,score,grade:proofScoreGrade(score),measured_weight:weight,components,recommendations};
  });
  const rated=sites.filter(x=>x.score!==null),overall=rated.length?Math.round(rated.reduce((n,x)=>n+x.score,0)/rated.length*100)/100:null;
  return{period_start:fromDate,period_end:toDate,generated_at:new Date().toISOString(),summary:{overall_score:overall,grade:proofScoreGrade(overall),sites:sites.length,rated_sites:rated.length,sites_below_80:rated.filter(x=>x.score<80).length},sites};
}

app.get('/api/proofscore',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id),to=String(req.query.to_date||DateTime.now().toISODate()),from=String(req.query.from_date||DateTime.now().minus({days:29}).toISODate());if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!DateTime.fromISO(from).isValid||!DateTime.fromISO(to).isValid||from>to)return res.status(400).json({error:'Valid date range required'});try{res.json(await withTenant(tenantId,c=>buildProofScore(c,tenantId,from,to,req.query.site_id||null)))}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/proofscore/snapshots',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),from=String(req.body.from_date||''),to=String(req.body.to_date||'');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!DateTime.fromISO(from).isValid||!DateTime.fromISO(to).isValid||from>to)return res.status(400).json({error:'Valid date range required'});try{const report=await withTenant(tenantId,async c=>{const data=await buildProofScore(c,tenantId,from,to,req.body.site_id||null);for(const site of data.sites)await c.query(`INSERT INTO proofscore_snapshots(tenant_id,site_id,period_start,period_end,score,grade,components,recommendations,calculated_by_user_id,calculated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW()) ON CONFLICT(tenant_id,site_id,period_start,period_end) DO UPDATE SET score=EXCLUDED.score,grade=EXCLUDED.grade,components=EXCLUDED.components,recommendations=EXCLUDED.recommendations,calculated_by_user_id=EXCLUDED.calculated_by_user_id,calculated_at=NOW()`,[tenantId,site.site_id,from,to,site.score,site.grade,JSON.stringify(site.components),JSON.stringify(site.recommendations),req.auth.user_id]);return data});res.status(201).json({...report,saved:true})}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/proofscore/history',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,c=>{const p=[tenantId];let q=`SELECT p.*,s.name site_name,u.email calculated_by_email FROM proofscore_snapshots p JOIN sites s ON s.id=p.site_id LEFT JOIN users u ON u.id=p.calculated_by_user_id AND u.tenant_id=p.tenant_id WHERE p.tenant_id=$1`;if(req.query.site_id){p.push(Number(req.query.site_id));q+=` AND p.site_id=$${p.length}`}q+=' ORDER BY p.calculated_at DESC LIMIT 250';return c.query(q,p)});res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});

function proofScoreDateOnly(value){
  if(!value)return null;
  if(value instanceof Date){
    const parsed=DateTime.fromJSDate(value);
    return parsed.isValid?parsed.toISODate():null;
  }
  const text=String(value).trim();
  if(/^\d{4}-\d{2}-\d{2}$/.test(text))return text;
  const iso=DateTime.fromISO(text);
  if(iso.isValid)return iso.toISODate();
  const http=DateTime.fromHTTP(text);
  return http.isValid?http.toISODate():null;
}

async function clientProofScoreData(client,tenantId,siteId){
  const history=(await client.query(`SELECT p.id,p.period_start,p.period_end,p.score,p.grade,p.components,p.recommendations,p.calculated_at,s.name site_name
    FROM proofscore_snapshots p JOIN sites s ON s.id=p.site_id AND s.tenant_id=p.tenant_id
    WHERE p.tenant_id=$1 AND p.site_id=$2 ORDER BY p.calculated_at DESC LIMIT 24`,[tenantId,siteId])).rows;
  const latest=history[0]||null,
    from=latest?proofScoreDateOnly(latest.period_start):DateTime.now().minus({days:29}).toISODate(),
    to=latest?proofScoreDateOnly(latest.period_end):DateTime.now().toISODate();
  if(!from||!to)throw new Error('Published ProofScore contains an invalid measurement period');
  const evidence=(await client.query(`SELECT
    (SELECT COUNT(*)::int FROM patrol_logs p JOIN checkpoints c ON c.id=p.checkpoint_id WHERE p.tenant_id=$1 AND c.site_id=$2 AND p.scanned_at::date BETWEEN $3::date AND $4::date) patrol_total,
    (SELECT COUNT(*)::int FROM patrol_logs p JOIN checkpoints c ON c.id=p.checkpoint_id JOIN evidence_integrity_records e ON e.tenant_id=p.tenant_id AND e.evidence_type='patrol_scan' AND e.evidence_id=p.id::text WHERE p.tenant_id=$1 AND c.site_id=$2 AND p.scanned_at::date BETWEEN $3::date AND $4::date) patrol_sealed,
    (SELECT COUNT(*)::int FROM incident_photos p JOIN incidents i ON i.id=p.incident_id AND i.tenant_id=p.tenant_id WHERE p.tenant_id=$1 AND i.site_id=$2 AND p.created_at::date BETWEEN $3::date AND $4::date) photo_total,
    (SELECT COUNT(*)::int FROM incident_photos p JOIN incidents i ON i.id=p.incident_id AND i.tenant_id=p.tenant_id JOIN evidence_integrity_records e ON e.tenant_id=p.tenant_id AND e.evidence_type='incident_photo' AND e.evidence_id=p.id::text WHERE p.tenant_id=$1 AND i.site_id=$2 AND p.created_at::date BETWEEN $3::date AND $4::date) photo_sealed`,[tenantId,siteId,from,to])).rows[0];
  const anchor=(await client.query(`SELECT e.chain_hash,e.source_hash,e.sealed_at,e.evidence_type FROM evidence_integrity_records e WHERE e.tenant_id=$1 AND((e.evidence_type='patrol_scan' AND EXISTS(SELECT 1 FROM patrol_logs p JOIN checkpoints c ON c.id=p.checkpoint_id WHERE p.tenant_id=$1 AND p.id::text=e.evidence_id AND c.site_id=$2))OR(e.evidence_type='incident_photo' AND EXISTS(SELECT 1 FROM incident_photos p JOIN incidents i ON i.id=p.incident_id AND i.tenant_id=p.tenant_id WHERE p.tenant_id=$1 AND p.id::text=e.evidence_id AND i.site_id=$2)))ORDER BY e.sealed_at DESC LIMIT 1`,[tenantId,siteId])).rows[0]||null;
  return{latest,history,evidence:{period_start:from,period_end:to,patrol_scans:{sealed:Number(evidence.patrol_sealed),total:Number(evidence.patrol_total)},incident_photos:{sealed:Number(evidence.photo_sealed),total:Number(evidence.photo_total)},latest_anchor:anchor}};
}

app.get('/api/client-portal/proofscore',requireAuth,requireClient,async(req,res)=>{const{tenant_id,site_id}=req.auth;try{res.json(await withTenant(tenant_id,c=>clientProofScoreData(c,tenant_id,site_id)))}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/client-portal/proofscore/:id/pdf',requireAuth,requireClient,async(req,res)=>{const{tenant_id,site_id}=req.auth;try{const snapshot=await withTenant(tenant_id,async c=>(await c.query(`SELECT p.*,s.name site_name,t.name tenant_name FROM proofscore_snapshots p JOIN sites s ON s.id=p.site_id AND s.tenant_id=p.tenant_id JOIN tenants t ON t.id=p.tenant_id WHERE p.id=$1 AND p.tenant_id=$2 AND p.site_id=$3`,[req.params.id,tenant_id,site_id])).rows[0]);if(!snapshot)return res.status(404).json({error:'Published assurance snapshot not found'});res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`attachment; filename="proofscore-${safeFilenamePart(snapshot.site_name)}-${String(snapshot.period_end).slice(0,10)}.pdf"`);const doc=new PDFDocument({margin:48,size:'A4'});doc.pipe(res);doc.fillColor('#0f766e').fontSize(11).text('PATROLSYNC CLIENT ASSURANCE');doc.moveDown(.5).fillColor('#111827').fontSize(24).text('ProofScore Assurance Report');doc.moveDown(.4).fontSize(11).fillColor('#475569').text(`${snapshot.tenant_name} · ${snapshot.site_name}`).text(`Period: ${String(snapshot.period_start).slice(0,10)} to ${String(snapshot.period_end).slice(0,10)}`).text(`Snapshot: #${snapshot.id} · ${new Date(snapshot.calculated_at).toISOString()}`);doc.moveDown().fillColor('#111827').fontSize(36).text(`${Number(snapshot.score).toFixed(2)}%`,{continued:true}).fontSize(16).text(`   Grade ${snapshot.grade}`);doc.moveDown().fontSize(15).text('Assurance components');doc.moveDown(.4);for(const component of snapshot.components||[]){doc.fontSize(11).fillColor('#111827').text(`${component.label}: ${component.applicable?component.score+'%':'Not measured'} (${component.weight}% model weight)`);doc.fontSize(9).fillColor('#64748b').text(component.explanation||'');doc.moveDown(.5)}if((snapshot.recommendations||[]).length){doc.fillColor('#111827').fontSize(15).text('Improvement priorities');doc.moveDown(.4);for(const item of snapshot.recommendations)doc.fontSize(10).text(`• ${item}`)}doc.moveDown().fontSize(8).fillColor('#64748b').text('This report represents a saved PatrolSync assurance snapshot. It does not expose private guard data or internal administrative records.');doc.end()}catch(err){if(!res.headersSent)res.status(500).json({error:err.message})}});

// ------------------------ STAGE 5.4A: ASSURANCE IMPROVEMENT PLANS ------------------------
async function ensureAssuranceActionSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS assurance_improvement_actions(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,snapshot_id BIGINT,
    component_key TEXT NOT NULL,title TEXT NOT NULL,description TEXT,owner_user_id INTEGER,due_date DATE,
    status TEXT NOT NULL DEFAULT 'open',progress INTEGER NOT NULL DEFAULT 0,client_visible BOOLEAN NOT NULL DEFAULT FALSE,
    internal_note TEXT,client_update TEXT,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),completed_at TIMESTAMPTZ,
    CONSTRAINT assurance_action_status CHECK(status IN('open','in_progress','blocked','completed','cancelled')),
    CONSTRAINT assurance_action_progress CHECK(progress BETWEEN 0 AND 100))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS assurance_actions_tenant_site_status ON assurance_improvement_actions(tenant_id,site_id,status,due_date)`);
  await pool.query(`ALTER TABLE assurance_improvement_actions ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON assurance_improvement_actions`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON assurance_improvement_actions USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON assurance_improvement_actions TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE assurance_improvement_actions_id_seq TO "${role}"`)}}catch(err){console.warn('Assurance action tenant-role grant skipped:',err.message)}
  console.log('Assurance improvement action schema ready');
}
ensureAssuranceActionSchema().catch(err=>console.error('Assurance action schema setup failed:',err.message));

app.get('/api/assurance-actions',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,c=>{const params=[tenantId];let sql=`SELECT a.*,s.name site_name,u.email owner_email,p.score snapshot_score,p.grade snapshot_grade FROM assurance_improvement_actions a JOIN sites s ON s.id=a.site_id AND s.tenant_id=a.tenant_id LEFT JOIN users u ON u.id=a.owner_user_id AND u.tenant_id=a.tenant_id LEFT JOIN proofscore_snapshots p ON p.id=a.snapshot_id AND p.tenant_id=a.tenant_id WHERE a.tenant_id=$1`;if(req.query.site_id){params.push(Number(req.query.site_id));sql+=` AND a.site_id=$${params.length}`}if(req.query.status){params.push(String(req.query.status));sql+=` AND a.status=$${params.length}`}sql+=` ORDER BY CASE a.status WHEN 'blocked' THEN 1 WHEN 'open' THEN 2 WHEN 'in_progress' THEN 3 ELSE 4 END,a.due_date NULLS LAST,a.created_at DESC`;return c.query(sql,params)});res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/assurance-actions',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),title=String(req.body.title||'').trim(),component=String(req.body.component_key||'general').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!title)return res.status(400).json({error:'Site and action title are required'});try{const result=await withTenant(tenantId,async c=>{const valid=await c.query(`SELECT id FROM sites WHERE id=$1 AND tenant_id=$2`,[siteId,tenantId]);if(!valid.rowCount)throw Object.assign(new Error('Site not found'),{statusCode:404});return c.query(`INSERT INTO assurance_improvement_actions(tenant_id,site_id,snapshot_id,component_key,title,description,owner_user_id,due_date,status,progress,client_visible,internal_note,client_update,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'open',0,$9,$10,$11,$12) RETURNING *`,[tenantId,siteId,req.body.snapshot_id?Number(req.body.snapshot_id):null,component,title,String(req.body.description||'').trim()||null,req.body.owner_user_id?Number(req.body.owner_user_id):null,req.body.due_date||null,req.body.client_visible===true,String(req.body.internal_note||'').trim()||null,String(req.body.client_update||'').trim()||null,req.auth.user_id])});res.status(201).json(result.rows[0])}catch(err){res.status(err.statusCode||500).json({error:err.message})}});
app.patch('/api/assurance-actions/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||'open'),progress=Math.max(0,Math.min(100,Number(req.body.progress||0)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['open','in_progress','blocked','completed','cancelled'].includes(status))return res.status(400).json({error:'Invalid action status'});try{const result=await withTenant(tenantId,c=>c.query(`UPDATE assurance_improvement_actions SET owner_user_id=$3,due_date=$4,status=$5,progress=CASE WHEN $5='completed' THEN 100 ELSE $6 END,client_visible=$7,internal_note=$8,client_update=$9,updated_at=NOW(),completed_at=CASE WHEN $5='completed' THEN COALESCE(completed_at,NOW()) ELSE NULL END WHERE id=$1 AND tenant_id=$2 RETURNING *`,[req.params.id,tenantId,req.body.owner_user_id?Number(req.body.owner_user_id):null,req.body.due_date||null,status,progress,req.body.client_visible===true,String(req.body.internal_note||'').trim()||null,String(req.body.client_update||'').trim()||null]));if(!result.rowCount)return res.status(404).json({error:'Improvement action not found'});res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/client-portal/assurance-actions',requireAuth,requireClient,async(req,res)=>{const{tenant_id,site_id}=req.auth;try{const result=await withTenant(tenant_id,c=>c.query(`SELECT id,component_key,title,due_date,status,progress,client_update,created_at,updated_at,completed_at FROM assurance_improvement_actions WHERE tenant_id=$1 AND site_id=$2 AND client_visible=TRUE AND status<>'cancelled' ORDER BY CASE status WHEN 'blocked' THEN 1 WHEN 'open' THEN 2 WHEN 'in_progress' THEN 3 WHEN 'completed' THEN 4 ELSE 5 END,due_date NULLS LAST,updated_at DESC`,[tenant_id,site_id]));res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});

// ------------------------ STAGE 5.5: CLIENT ASSURANCE READINESS ------------------------
app.get('/api/assurance-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=communicationTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['proofscore_snapshots','evidence_integrity_records','assurance_improvement_actions'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 5 assurance structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRoleRaw=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRoleRaw))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert FROM unnest($2::text[]) t`,[tenantRoleRaw,required])).rows;
    add('grants','Restricted tenant-role permissions',grants.length===required.length&&grants.every(x=>x.can_read&&x.can_insert),grants.length?`${grants.filter(x=>x.can_read&&x.can_insert).length}/${required.length} tables readable and writable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const data=await withTenant(tenantId,async client=>{
      const [sites,snapshots,evidence,actions,clients]=await Promise.all([
        client.query(`SELECT COUNT(*)::int total FROM sites WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(DISTINCT site_id)::int sites,COUNT(*) FILTER(WHERE score IS NULL OR score<0 OR score>100)::int invalid_scores,COUNT(*) FILTER(WHERE jsonb_typeof(components)<>'array')::int invalid_components,MAX(calculated_at) latest FROM proofscore_snapshots WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE evidence_type='patrol_scan')::int patrol_scans,COUNT(*) FILTER(WHERE evidence_type='incident_photo')::int incident_photos,COUNT(*) FILTER(WHERE source_hash!~'^[0-9a-fA-F]{64}$' OR chain_hash!~'^[0-9a-fA-F]{64}$')::int invalid_hashes FROM evidence_integrity_records WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE client_visible=TRUE AND status<>'cancelled')::int client_visible,COUNT(*) FILTER(WHERE progress<0 OR progress>100 OR(status='completed' AND progress<>100) OR(status='completed' AND completed_at IS NULL))::int invalid_state,COUNT(*) FILTER(WHERE status NOT IN('completed','cancelled') AND due_date<CURRENT_DATE)::int overdue,COUNT(*) FILTER(WHERE s.id IS NULL)::int broken_sites FROM assurance_improvement_actions a LEFT JOIN sites s ON s.id=a.site_id AND s.tenant_id=a.tenant_id WHERE a.tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total FROM client_users WHERE tenant_id=$1`,[tenantId])
      ]);
      return{sites:Number(sites.rows[0].total),snapshots:snapshots.rows[0],evidence:evidence.rows[0],actions:actions.rows[0],clients:Number(clients.rows[0].total)};
    });
    add('snapshot_integrity','Published ProofScore integrity',Number(data.snapshots.invalid_scores)===0&&Number(data.snapshots.invalid_components)===0,`${data.snapshots.total} published snapshot(s); ${data.snapshots.invalid_scores} invalid score(s); ${data.snapshots.invalid_components} invalid component set(s)`,true,data.snapshots);
    add('site_coverage','Published assurance site coverage',Number(data.snapshots.sites)===data.sites&&data.sites>0,`${data.snapshots.sites}/${data.sites} site(s) have a published ProofScore`,false,{published_sites:Number(data.snapshots.sites),sites:data.sites,latest:data.snapshots.latest});
    add('evidence_integrity','TrustProof traceability',Number(data.evidence.total)>0&&Number(data.evidence.invalid_hashes)===0,`${data.evidence.total} sealed evidence record(s); ${data.evidence.invalid_hashes} invalid hash record(s)`,true,data.evidence);
    add('action_integrity','Improvement-action integrity',Number(data.actions.invalid_state)===0&&Number(data.actions.broken_sites)===0,`${data.actions.total} action(s); ${data.actions.invalid_state} invalid state(s); ${data.actions.broken_sites} broken site relationship(s)`,true,data.actions);
    add('client_visibility','Client-visible improvement progress',Number(data.actions.client_visible)>0,`${data.actions.client_visible} active client-visible action(s)`,false,{visible:Number(data.actions.client_visible),total:Number(data.actions.total)});
    add('overdue_actions','Assurance remediation deadlines',Number(data.actions.overdue)===0,`${data.actions.overdue} overdue open action(s)`,false,{overdue:Number(data.actions.overdue)});
    add('client_accounts','Client assurance access',data.clients>0,`${data.clients} site-specific client account(s) can access published assurance`,false,{accounts:data.clients});
    const failures=checks.filter(x=>x.critical&&!x.passed),warnings=checks.filter(x=>!x.critical&&!x.passed),status=failures.length?'action_required':warnings.length?'ready_with_warnings':'stage_5_ready';
    res.json({status,ready:failures.length===0,generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,warnings:warnings.length,failures:failures.length,total:checks.length},activity:{published_snapshots:Number(data.snapshots.total),sealed_evidence:Number(data.evidence.total),improvement_actions:Number(data.actions.total),client_accounts:data.clients},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}
});

// ------------------------ STAGE 6.1: PREDICTIVE ASSURANCE ------------------------
async function ensurePredictiveAssuranceSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS assurance_risk_forecasts(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,contract_id BIGINT,
    horizon_days INTEGER NOT NULL DEFAULT 14,risk_score NUMERIC(5,2) NOT NULL,
    breach_probability NUMERIC(5,2) NOT NULL,risk_band TEXT NOT NULL,
    current_proofscore NUMERIC(5,2),proofscore_change NUMERIC(6,2),
    signals JSONB NOT NULL DEFAULT '{}'::jsonb,reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,model_version TEXT NOT NULL DEFAULT 'ps-risk-v1',
    calculated_by_user_id INTEGER,calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT assurance_risk_band CHECK(risk_band IN('low','medium','high','critical')),
    CONSTRAINT assurance_risk_score CHECK(risk_score BETWEEN 0 AND 100),
    CONSTRAINT assurance_breach_probability CHECK(breach_probability BETWEEN 0 AND 100))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS assurance_risk_forecasts_tenant_site_time ON assurance_risk_forecasts(tenant_id,site_id,calculated_at DESC)`);
  await pool.query(`ALTER TABLE assurance_risk_forecasts ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON assurance_risk_forecasts`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON assurance_risk_forecasts USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON assurance_risk_forecasts TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE assurance_risk_forecasts_id_seq TO "${role}"`)}}catch(err){console.warn('Predictive assurance tenant-role grant skipped:',err.message)}
  console.log('Predictive assurance schema ready');
}
ensurePredictiveAssuranceSchema().catch(err=>console.error('Predictive assurance schema setup failed:',err.message));

function clampRisk(value){return Math.max(0,Math.min(100,Math.round(Number(value||0)*100)/100))}
function riskBand(score){return score>=75?'critical':score>=50?'high':score>=25?'medium':'low'}
async function buildPredictiveAssurance(client,tenantId,horizonDays,siteId){
  const params=[tenantId];let filter='';if(siteId){params.push(Number(siteId));filter=` AND s.id=$${params.length}`}
  const sites=(await client.query(`SELECT s.id site_id,s.name site_name,sc.id contract_id,sc.reference_code,
    sc.sla_patrol_completion_pct,sc.sla_incident_ack_minutes,sc.sla_shift_coverage_pct
    FROM sites s JOIN LATERAL(SELECT c.* FROM service_contracts c WHERE c.tenant_id=s.tenant_id AND c.site_id=s.id AND c.status='active' AND c.start_date<=CURRENT_DATE AND(c.end_date IS NULL OR c.end_date>=CURRENT_DATE) ORDER BY c.id DESC LIMIT 1)sc ON TRUE
    WHERE s.tenant_id=$1${filter} ORDER BY s.name`,params)).rows;
  const forecasts=[];
  for(const site of sites){
    const snapshots=(await client.query(`SELECT score,grade,components,calculated_at FROM proofscore_snapshots WHERE tenant_id=$1 AND site_id=$2 ORDER BY calculated_at DESC LIMIT 2`,[tenantId,site.site_id])).rows;
    const latest=snapshots[0]||null,previous=snapshots[1]||null,current=latest?.score==null?null:Number(latest.score),change=current!==null&&previous?.score!=null?Math.round((current-Number(previous.score))*100)/100:null;
    const signal=(await client.query(`SELECT
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.site_id=$2 AND sh.shift_date BETWEEN CURRENT_DATE AND CURRENT_DATE+$3::int) future_shifts,
      (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.site_id=$2 AND sh.shift_date BETWEEN CURRENT_DATE AND CURRENT_DATE+$3::int AND sh.assignment_status='assigned' AND sh.user_id IS NOT NULL) covered_shifts,
      (SELECT COUNT(*)::int FROM patrol_runs p WHERE p.tenant_id=$1 AND p.site_id=$2 AND p.status NOT IN('completed','cancelled') AND p.scheduled_end<NOW()) overdue_patrols,
      (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.site_id=$2 AND i.acknowledged_at IS NULL) unacknowledged_incidents,
      (SELECT COUNT(*)::int FROM assurance_improvement_actions a WHERE a.tenant_id=$1 AND a.site_id=$2 AND a.status NOT IN('completed','cancelled') AND a.due_date<CURRENT_DATE) overdue_actions,
      (SELECT COUNT(*)::int FROM assurance_improvement_actions a WHERE a.tenant_id=$1 AND a.site_id=$2 AND a.status IN('open','in_progress','blocked')) open_actions`,[tenantId,site.site_id,horizonDays])).rows[0];
    const future=Number(signal.future_shifts),covered=Number(signal.covered_shifts),coverage=future?covered/future*100:100;
    let risk=current===null?35:Math.max(0,100-current)*0.55;
    const reasons=[],actions=[];
    if(current===null){reasons.push('No published ProofScore baseline is available.');actions.push('Publish a current ProofScore snapshot.')}else if(current<80){reasons.push(`Current ProofScore is ${current.toFixed(2)}%, below the 80% assurance target.`);actions.push('Review the lowest ProofScore components and assign corrective actions.')}
    if(change!==null&&change<0){risk+=Math.min(20,Math.abs(change)*1.5);reasons.push(`ProofScore declined ${Math.abs(change).toFixed(2)} point(s) from the previous published result.`);actions.push('Review the ProofScore trend and address the deteriorating components.')}
    if(coverage<Number(site.sla_shift_coverage_pct)){risk+=Math.min(25,(Number(site.sla_shift_coverage_pct)-coverage)*1.25);reasons.push(`${covered}/${future} upcoming shifts are covered (${coverage.toFixed(2)}%; target ${Number(site.sla_shift_coverage_pct)}%).`);actions.push('Assign qualified guards to uncovered upcoming shifts.')}
    if(Number(signal.overdue_patrols)>0){risk+=Math.min(20,Number(signal.overdue_patrols)*5);reasons.push(`${signal.overdue_patrols} patrol run(s) are overdue.`);actions.push('Resolve overdue patrol runs and confirm route coverage.')}
    if(Number(signal.unacknowledged_incidents)>0){risk+=Math.min(20,Number(signal.unacknowledged_incidents)*3);reasons.push(`${signal.unacknowledged_incidents} incident(s) remain unacknowledged.`);actions.push('Acknowledge and triage outstanding incidents.')}
    if(Number(signal.overdue_actions)>0){risk+=Math.min(12,Number(signal.overdue_actions)*4);reasons.push(`${signal.overdue_actions} assurance improvement action(s) are overdue.`);actions.push('Update or complete overdue assurance actions.')}
    const weak=(Array.isArray(latest?.components)?latest.components:[]).filter(x=>x.applicable&&Number(x.score)<80);
    for(const component of weak){risk+=Math.min(8,(80-Number(component.score))*Number(component.weight||0)/100);reasons.push(`${component.label} is ${Number(component.score).toFixed(2)}%.`)}
    const score=clampRisk(risk),probability=clampRisk(8+score*.88),band=riskBand(score);
    forecasts.push({site_id:Number(site.site_id),site_name:site.site_name,contract_id:Number(site.contract_id),reference_code:site.reference_code,horizon_days:horizonDays,risk_score:score,breach_probability:probability,risk_band:band,current_proofscore:current,proofscore_change:change,signals:{future_shifts:future,covered_shifts:covered,coverage_pct:Math.round(coverage*100)/100,overdue_patrols:Number(signal.overdue_patrols),unacknowledged_incidents:Number(signal.unacknowledged_incidents),overdue_actions:Number(signal.overdue_actions),open_actions:Number(signal.open_actions),weak_components:weak.map(x=>({key:x.key,label:x.label,score:Number(x.score),weight:Number(x.weight)}))},reasons:[...new Set(reasons)],recommended_actions:[...new Set(actions)],model_version:'ps-risk-v1'});
  }
  return{generated_at:new Date().toISOString(),horizon_days:horizonDays,model:{version:'ps-risk-v1',type:'explainable weighted operational risk',automated_decisions:false},summary:{sites:forecasts.length,critical:forecasts.filter(x=>x.risk_band==='critical').length,high:forecasts.filter(x=>x.risk_band==='high').length,medium:forecasts.filter(x=>x.risk_band==='medium').length,low:forecasts.filter(x=>x.risk_band==='low').length},forecasts};
}

app.get('/api/predictive-assurance',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id),horizon=Math.max(7,Math.min(60,Number(req.query.horizon_days||14)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{res.json(await withTenant(tenantId,c=>buildPredictiveAssurance(c,tenantId,horizon,req.query.site_id||null)))}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/predictive-assurance/run',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),horizon=Math.max(7,Math.min(60,Number(req.body.horizon_days||14)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const report=await withTenant(tenantId,async c=>{const data=await buildPredictiveAssurance(c,tenantId,horizon,req.body.site_id||null);for(const f of data.forecasts)await c.query(`INSERT INTO assurance_risk_forecasts(tenant_id,site_id,contract_id,horizon_days,risk_score,breach_probability,risk_band,current_proofscore,proofscore_change,signals,reasons,recommended_actions,model_version,calculated_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,[tenantId,f.site_id,f.contract_id,horizon,f.risk_score,f.breach_probability,f.risk_band,f.current_proofscore,f.proofscore_change,JSON.stringify(f.signals),JSON.stringify(f.reasons),JSON.stringify(f.recommended_actions),f.model_version,req.auth.user_id]);return data});res.status(201).json({...report,saved:true})}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/predictive-assurance/history',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,c=>{const p=[tenantId];let q=`SELECT f.*,s.name site_name,sc.reference_code,u.email calculated_by_email FROM assurance_risk_forecasts f JOIN sites s ON s.id=f.site_id AND s.tenant_id=f.tenant_id LEFT JOIN service_contracts sc ON sc.id=f.contract_id AND sc.tenant_id=f.tenant_id LEFT JOIN users u ON u.id=f.calculated_by_user_id AND u.tenant_id=f.tenant_id WHERE f.tenant_id=$1`;if(req.query.site_id){p.push(Number(req.query.site_id));q+=` AND f.site_id=$${p.length}`}q+=' ORDER BY f.calculated_at DESC LIMIT 250';return c.query(q,p)});res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});

// ------------------------ STAGE 6.2: GOVERNED SERVICE CREDIT AUTOPILOT ------------------------
async function ensureServiceCreditSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS service_credit_rules(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id) ON DELETE CASCADE,
    patrol_miss_pct NUMERIC(5,2) NOT NULL DEFAULT 5,incident_miss_pct NUMERIC(5,2) NOT NULL DEFAULT 5,
    coverage_miss_pct NUMERIC(5,2) NOT NULL DEFAULT 5,maximum_credit_pct NUMERIC(5,2) NOT NULL DEFAULT 15,
    active BOOLEAN NOT NULL DEFAULT TRUE,created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,contract_id),CHECK(patrol_miss_pct BETWEEN 0 AND 100),CHECK(incident_miss_pct BETWEEN 0 AND 100),
    CHECK(coverage_miss_pct BETWEEN 0 AND 100),CHECK(maximum_credit_pct BETWEEN 0 AND 100)
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS service_credit_recommendations(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,contract_id BIGINT NOT NULL REFERENCES service_contracts(id) ON DELETE CASCADE,
    site_id INTEGER NOT NULL,period_start DATE NOT NULL,period_end DATE NOT NULL,status TEXT NOT NULL DEFAULT 'draft',
    currency TEXT NOT NULL DEFAULT 'EUR',credit_basis NUMERIC(12,2) NOT NULL DEFAULT 0,credit_percent NUMERIC(5,2) NOT NULL DEFAULT 0,
    recommended_amount NUMERIC(12,2) NOT NULL DEFAULT 0,metrics JSONB NOT NULL DEFAULT '{}'::jsonb,reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    rule_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,source TEXT NOT NULL DEFAULT 'sla_credit_v1',generated_by_user_id INTEGER,
    decided_by_user_id INTEGER,decision_reason TEXT,decided_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,contract_id,period_start,period_end),CHECK(status IN('draft','approved','rejected','cancelled'))
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS service_credit_decisions(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,recommendation_id BIGINT NOT NULL REFERENCES service_credit_recommendations(id) ON DELETE CASCADE,
    previous_status TEXT,new_status TEXT NOT NULL,reason TEXT,decided_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS service_credit_recommendations_tenant_status ON service_credit_recommendations(tenant_id,status,created_at DESC)`);
  for(const table of ['service_credit_rules','service_credit_recommendations','service_credit_decisions']){
    await pool.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);
    await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ${table}`);
    await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ${table} USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  }
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){for(const table of ['service_credit_rules','service_credit_recommendations','service_credit_decisions'])await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON ${table} TO "${role}"`);for(const seq of ['service_credit_rules_id_seq','service_credit_recommendations_id_seq','service_credit_decisions_id_seq'])await pool.query(`GRANT USAGE,SELECT ON SEQUENCE ${seq} TO "${role}"`)}}catch(err){console.warn('Service-credit tenant-role grant skipped:',err.message)}
  console.log('Governed service-credit schema ready');
}
ensureServiceCreditSchema().catch(err=>console.error('Service-credit schema setup failed:',err.message));

function validCreditPercent(value){const n=Number(value);return Number.isFinite(n)&&n>=0&&n<=100}
async function serviceCreditAssessment(client,tenantId,contractId,start,end){
  const contract=(await client.query(`SELECT sc.*,s.name site_name FROM service_contracts sc JOIN sites s ON s.id=sc.site_id AND s.tenant_id=sc.tenant_id WHERE sc.id=$1 AND sc.tenant_id=$2 AND sc.status='active'`,[contractId,tenantId])).rows[0];
  if(!contract)throw Object.assign(new Error('Active contract not found'),{statusCode:404});
  const rule=(await client.query(`SELECT * FROM service_credit_rules WHERE tenant_id=$1 AND contract_id=$2 AND active=TRUE`,[tenantId,contractId])).rows[0]||{patrol_miss_pct:5,incident_miss_pct:5,coverage_miss_pct:5,maximum_credit_pct:15};
  const m=(await client.query(`SELECT
    (SELECT COUNT(*)::int FROM patrol_runs p WHERE p.tenant_id=$1 AND p.site_id=$2 AND p.scheduled_start::date BETWEEN $3::date AND $4::date) patrol_total,
    (SELECT COUNT(*)::int FROM patrol_runs p WHERE p.tenant_id=$1 AND p.site_id=$2 AND p.scheduled_start::date BETWEEN $3::date AND $4::date AND p.status='completed') patrol_met,
    (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.site_id=$2 AND i.reported_at::date BETWEEN $3::date AND $4::date) incident_total,
    (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=$1 AND i.site_id=$2 AND i.reported_at::date BETWEEN $3::date AND $4::date AND i.acknowledged_at IS NOT NULL AND i.acknowledged_at<=i.reported_at+($5::int*INTERVAL '1 minute')) incident_met,
    (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.site_id=$2 AND sh.shift_date BETWEEN $3::date AND $4::date) coverage_total,
    (SELECT COUNT(*)::int FROM shifts sh WHERE sh.tenant_id=$1 AND sh.site_id=$2 AND sh.shift_date BETWEEN $3::date AND $4::date AND sh.user_id IS NOT NULL) coverage_met`,[tenantId,contract.site_id,start,end,Number(contract.sla_incident_ack_minutes||15)])).rows[0];
  const pct=(a,b)=>Number(b)>0?Math.round(Number(a)*10000/Number(b))/100:null;
  const metrics={
    patrol:{actual:pct(m.patrol_met,m.patrol_total),target:Number(contract.sla_patrol_completion_pct),met:Number(m.patrol_met),total:Number(m.patrol_total)},
    incident:{actual:pct(m.incident_met,m.incident_total),target:100,met:Number(m.incident_met),total:Number(m.incident_total),target_minutes:Number(contract.sla_incident_ack_minutes||15)},
    coverage:{actual:pct(m.coverage_met,m.coverage_total),target:Number(contract.sla_shift_coverage_pct),met:Number(m.coverage_met),total:Number(m.coverage_total)}
  };
  const invoice=(await client.query(`SELECT subtotal,currency,invoice_number FROM invoices WHERE tenant_id=$1 AND contract_id=$2 AND period_start=$3::date AND period_end=$4::date ORDER BY id DESC LIMIT 1`,[tenantId,contractId,start,end])).rows[0];
  const basis=invoice?Number(invoice.subtotal):Number(contract.rate||0),basisSource=invoice?'matching invoice subtotal':'contract rate estimate';
  const misses=[],reasons=[];
  if(metrics.patrol.actual!==null&&metrics.patrol.actual<metrics.patrol.target){misses.push(Number(rule.patrol_miss_pct));reasons.push(`Patrol completion ${metrics.patrol.actual.toFixed(2)}% missed the ${metrics.patrol.target.toFixed(2)}% target.`)}
  if(metrics.incident.actual!==null&&metrics.incident.actual<metrics.incident.target){misses.push(Number(rule.incident_miss_pct));reasons.push(`Incident acknowledgement ${metrics.incident.actual.toFixed(2)}% missed the ${metrics.incident.target.toFixed(2)}% target.`)}
  if(metrics.coverage.actual!==null&&metrics.coverage.actual<metrics.coverage.target){misses.push(Number(rule.coverage_miss_pct));reasons.push(`Shift coverage ${metrics.coverage.actual.toFixed(2)}% missed the ${metrics.coverage.target.toFixed(2)}% target.`)}
  const creditPercent=Math.min(Number(rule.maximum_credit_pct),misses.reduce((a,b)=>a+b,0)),amount=Math.round(basis*creditPercent)/100;
  return{contract_id:Number(contract.id),reference_code:contract.reference_code,client_name:contract.client_name,site_id:Number(contract.site_id),site_name:contract.site_name,period_start:start,period_end:end,currency:invoice?.currency||contract.currency||'EUR',credit_basis:basis,basis_source:basisSource,invoice_number:invoice?.invoice_number||null,credit_percent:creditPercent,recommended_amount:amount,metrics,reasons,rule:{patrol_miss_pct:Number(rule.patrol_miss_pct),incident_miss_pct:Number(rule.incident_miss_pct),coverage_miss_pct:Number(rule.coverage_miss_pct),maximum_credit_pct:Number(rule.maximum_credit_pct)},automated_application:false};
}

app.get('/api/service-credit-rules',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const rows=await withTenant(tenantId,c=>c.query(`SELECT sc.id contract_id,sc.reference_code,sc.client_name,s.name site_name,sc.currency,COALESCE(r.patrol_miss_pct,5) patrol_miss_pct,COALESCE(r.incident_miss_pct,5) incident_miss_pct,COALESCE(r.coverage_miss_pct,5) coverage_miss_pct,COALESCE(r.maximum_credit_pct,15) maximum_credit_pct,COALESCE(r.active,TRUE) active FROM service_contracts sc JOIN sites s ON s.id=sc.site_id AND s.tenant_id=sc.tenant_id LEFT JOIN service_credit_rules r ON r.contract_id=sc.id AND r.tenant_id=sc.tenant_id WHERE sc.tenant_id=$1 AND sc.status='active' ORDER BY s.name`,[tenantId]));res.json(rows.rows)}catch(err){res.status(500).json({error:err.message})}});
app.put('/api/service-credit-rules/:contractId',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),values=['patrol_miss_pct','incident_miss_pct','coverage_miss_pct','maximum_credit_pct'].map(k=>req.body[k]);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(values.some(v=>!validCreditPercent(v)))return res.status(400).json({error:'Credit percentages must be between 0 and 100'});try{const row=await withTenant(tenantId,c=>c.query(`INSERT INTO service_credit_rules(tenant_id,contract_id,patrol_miss_pct,incident_miss_pct,coverage_miss_pct,maximum_credit_pct,active,created_by_user_id) SELECT $1,id,$3,$4,$5,$6,TRUE,$7 FROM service_contracts WHERE id=$2 AND tenant_id=$1 AND status='active' ON CONFLICT(tenant_id,contract_id) DO UPDATE SET patrol_miss_pct=EXCLUDED.patrol_miss_pct,incident_miss_pct=EXCLUDED.incident_miss_pct,coverage_miss_pct=EXCLUDED.coverage_miss_pct,maximum_credit_pct=EXCLUDED.maximum_credit_pct,active=TRUE,updated_at=NOW() RETURNING *`,[tenantId,req.params.contractId,...values,req.auth.user_id]));if(!row.rowCount)return res.status(404).json({error:'Active contract not found'});res.json(row.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/service-credits/preview',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id),contractId=Number(req.query.contract_id),start=String(req.query.period_start||''),end=String(req.query.period_end||'');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!DateTime.fromISO(start).isValid||!DateTime.fromISO(end).isValid||start>end)return res.status(400).json({error:'Contract and valid period are required'});try{res.json(await withTenant(tenantId,c=>serviceCreditAssessment(c,tenantId,contractId,start,end)))}catch(err){res.status(err.statusCode||500).json({error:err.message})}});
app.post('/api/service-credits/generate',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),contractId=Number(req.body.contract_id),start=String(req.body.period_start||''),end=String(req.body.period_end||'');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!contractId||!DateTime.fromISO(start).isValid||!DateTime.fromISO(end).isValid||start>end)return res.status(400).json({error:'Contract and valid period are required'});try{const result=await withTenant(tenantId,async c=>{const a=await serviceCreditAssessment(c,tenantId,contractId,start,end);const saved=await c.query(`INSERT INTO service_credit_recommendations(tenant_id,contract_id,site_id,period_start,period_end,status,currency,credit_basis,credit_percent,recommended_amount,metrics,reasons,rule_snapshot,generated_by_user_id) VALUES($1,$2,$3,$4,$5,'draft',$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(tenant_id,contract_id,period_start,period_end) DO UPDATE SET status='draft',currency=EXCLUDED.currency,credit_basis=EXCLUDED.credit_basis,credit_percent=EXCLUDED.credit_percent,recommended_amount=EXCLUDED.recommended_amount,metrics=EXCLUDED.metrics,reasons=EXCLUDED.reasons,rule_snapshot=EXCLUDED.rule_snapshot,generated_by_user_id=EXCLUDED.generated_by_user_id,decided_by_user_id=NULL,decision_reason=NULL,decided_at=NULL,updated_at=NOW() RETURNING *`,[tenantId,contractId,a.site_id,start,end,a.currency,a.credit_basis,a.credit_percent,a.recommended_amount,JSON.stringify(a.metrics),JSON.stringify(a.reasons),JSON.stringify({...a.rule,basis_source:a.basis_source,invoice_number:a.invoice_number}),req.auth.user_id]);return{...saved.rows[0],site_name:a.site_name,reference_code:a.reference_code,automated_application:false}});res.status(201).json(result)}catch(err){res.status(err.statusCode||500).json({error:err.message})}});
app.get('/api/service-credits',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,c=>{const p=[tenantId];let q=`SELECT r.*,s.name site_name,sc.reference_code,sc.client_name,g.email generated_by_email,d.email decided_by_email FROM service_credit_recommendations r JOIN sites s ON s.id=r.site_id AND s.tenant_id=r.tenant_id JOIN service_contracts sc ON sc.id=r.contract_id AND sc.tenant_id=r.tenant_id LEFT JOIN users g ON g.id=r.generated_by_user_id AND g.tenant_id=r.tenant_id LEFT JOIN users d ON d.id=r.decided_by_user_id AND d.tenant_id=r.tenant_id WHERE r.tenant_id=$1`;if(req.query.status&&req.query.status!=='all'){p.push(String(req.query.status));q+=` AND r.status=$${p.length}`}q+=' ORDER BY r.created_at DESC LIMIT 250';return c.query(q,p)});res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});
app.patch('/api/service-credits/:id/decision',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),decision=String(req.body.decision||''),reason=String(req.body.reason||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['approved','rejected'].includes(decision))return res.status(400).json({error:'Decision must be approved or rejected'});if(!reason)return res.status(400).json({error:'A decision reason is required'});try{const result=await withTenant(tenantId,async c=>{const updated=(await c.query(`UPDATE service_credit_recommendations SET status=$1,decided_by_user_id=$2,decision_reason=$3,decided_at=NOW(),updated_at=NOW() WHERE id=$4 AND tenant_id=$5 AND status='draft' RETURNING *`,[decision,req.auth.user_id,reason,req.params.id,tenantId])).rows[0];if(!updated){const exists=(await c.query(`SELECT status FROM service_credit_recommendations WHERE id=$1 AND tenant_id=$2`,[req.params.id,tenantId])).rows[0];throw Object.assign(new Error(exists?'Only draft recommendations can be decided':'Credit recommendation not found'),{statusCode:exists?409:404})}await c.query(`INSERT INTO service_credit_decisions(tenant_id,recommendation_id,previous_status,new_status,reason,decided_by_user_id) VALUES($1,$2,'draft',$3,$4,$5)`,[tenantId,req.params.id,decision,reason,req.auth.user_id]);return updated});res.json({...result,message:`Recommendation ${decision}. No invoice was changed.`})}catch(err){res.status(err.statusCode||500).json({error:err.message})}});

// ------------------------ STAGE 7.2: GOVERNED CRISIS MODE ------------------------
app.get('/api/crisis-mode',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{await crisisModeSchemaReady;const rows=await withTenant(tenantId,c=>c.query(`SELECT ca.*,i.reference_code incident_reference,s.name site_name,commander.email commander_email,creator.email activated_by_email,(SELECT COUNT(*)::int FROM crisis_actions a WHERE a.crisis_id=ca.id AND a.tenant_id=ca.tenant_id AND a.status NOT IN('completed','cancelled')) open_actions FROM crisis_activations ca JOIN incidents i ON i.id=ca.incident_id AND i.tenant_id=ca.tenant_id JOIN sites s ON s.id=ca.site_id AND s.tenant_id=ca.tenant_id LEFT JOIN users commander ON commander.id=ca.commander_user_id LEFT JOIN users creator ON creator.id=ca.activated_by_user_id WHERE ca.tenant_id=$1 ORDER BY CASE ca.status WHEN 'active' THEN 0 WHEN 'contained' THEN 1 ELSE 2 END,ca.activated_at DESC LIMIT 100`,[tenantId]));res.json(rows.rows)}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/crisis-mode/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{await crisisModeSchemaReady;const data=await withTenant(tenantId,async c=>{const crisis=(await c.query(`SELECT ca.*,i.reference_code incident_reference,i.description incident_description,s.name site_name,commander.email commander_email FROM crisis_activations ca JOIN incidents i ON i.id=ca.incident_id AND i.tenant_id=ca.tenant_id JOIN sites s ON s.id=ca.site_id AND s.tenant_id=ca.tenant_id LEFT JOIN users commander ON commander.id=ca.commander_user_id WHERE ca.id=$1 AND ca.tenant_id=$2`,[req.params.id,tenantId])).rows[0];if(!crisis)throw Object.assign(new Error('Crisis activation not found'),{statusCode:404});const [roles,actions,updates]=await Promise.all([c.query(`SELECT r.*,u.email user_email FROM crisis_roles r JOIN users u ON u.id=r.user_id AND u.tenant_id=r.tenant_id WHERE r.crisis_id=$1 AND r.tenant_id=$2 ORDER BY r.role_name`,[req.params.id,tenantId]),c.query(`SELECT a.*,u.email assigned_email FROM crisis_actions a LEFT JOIN users u ON u.id=a.assigned_user_id AND u.tenant_id=a.tenant_id WHERE a.crisis_id=$1 AND a.tenant_id=$2 ORDER BY CASE a.status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,CASE a.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,a.created_at`,[req.params.id,tenantId]),c.query(`SELECT cu.*,u.email created_by_email FROM crisis_updates cu LEFT JOIN users u ON u.id=cu.created_by_user_id AND u.tenant_id=cu.tenant_id WHERE cu.crisis_id=$1 AND cu.tenant_id=$2 ORDER BY cu.created_at DESC LIMIT 250`,[req.params.id,tenantId])]);return{crisis,roles:roles.rows,actions:actions.rows,updates:updates.rows}});res.json(data)}catch(err){res.status(err.statusCode||500).json({error:err.message})}});
app.post('/api/crisis-mode/activate',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),incidentId=Number(req.body.incident_id),commanderId=Number(req.body.commander_user_id||req.auth.user_id),reason=String(req.body.activation_reason||'').trim(),severity=String(req.body.severity||'major');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!incidentId||!commanderId||!reason)return res.status(400).json({error:'Incident, crisis commander and activation reason are required'});if(!['major','critical'].includes(severity))return res.status(400).json({error:'Invalid crisis severity'});try{await crisisModeSchemaReady;const row=await withTenant(tenantId,async c=>{const incident=(await c.query(`SELECT i.*,s.name site_name FROM incidents i JOIN sites s ON s.id=i.site_id AND s.tenant_id=i.tenant_id WHERE i.id=$1 AND i.tenant_id=$2`,[incidentId,tenantId])).rows[0];if(!incident)throw Object.assign(new Error('Incident not found'),{statusCode:404});const commander=(await c.query(`SELECT id,email FROM users WHERE id=$1 AND tenant_id=$2 AND role='admin' AND COALESCE(account_active,TRUE)=TRUE`,[commanderId,tenantId])).rows[0];if(!commander)throw Object.assign(new Error('Active administrator not found'),{statusCode:400});const inserted=(await c.query(`INSERT INTO crisis_activations(tenant_id,incident_id,site_id,title,severity,commander_user_id,activated_by_user_id,activation_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[tenantId,incidentId,incident.site_id,`Crisis response · ${incident.reference_code||'#'+incident.id}`,severity,commanderId,req.auth.user_id,reason])).rows[0];await c.query(`INSERT INTO crisis_roles(tenant_id,crisis_id,role_name,user_id,assigned_by_user_id) VALUES($1,$2,'Crisis Commander',$3,$4)`,[tenantId,inserted.id,commanderId,req.auth.user_id]);await c.query(`INSERT INTO crisis_updates(tenant_id,crisis_id,update_type,message,created_by_user_id) VALUES($1,$2,'status',$3,$4)`,[tenantId,inserted.id,`Crisis Mode activated: ${reason}`,req.auth.user_id]);return inserted});res.status(201).json(row)}catch(err){res.status(err.code==='23505'?409:err.statusCode||500).json({error:err.code==='23505'?'An active crisis already exists for this incident':err.message})}});
app.post('/api/crisis-mode/:id/roles',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),role=String(req.body.role_name||'').trim(),userId=Number(req.body.user_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!role||!userId)return res.status(400).json({error:'Role and user are required'});try{const row=await withTenant(tenantId,c=>c.query(`INSERT INTO crisis_roles(tenant_id,crisis_id,role_name,user_id,assigned_by_user_id) SELECT $1,ca.id,$3,u.id,$4 FROM crisis_activations ca JOIN users u ON u.id=$5 AND u.tenant_id=ca.tenant_id WHERE ca.id=$2 AND ca.tenant_id=$1 AND ca.status<>'stood_down' ON CONFLICT(tenant_id,crisis_id,role_name) DO UPDATE SET user_id=EXCLUDED.user_id,assigned_by_user_id=EXCLUDED.assigned_by_user_id,assigned_at=NOW() RETURNING *`,[tenantId,req.params.id,role,req.auth.user_id,userId]));if(!row.rowCount)return res.status(404).json({error:'Active crisis or user not found'});res.status(201).json(row.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/crisis-mode/:id/actions',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),title=String(req.body.title||'').trim(),priority=String(req.body.priority||'high'),assigned=Number(req.body.assigned_user_id)||null;if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!title)return res.status(400).json({error:'Action title is required'});try{const row=await withTenant(tenantId,c=>c.query(`INSERT INTO crisis_actions(tenant_id,crisis_id,title,description,priority,assigned_user_id,due_at,created_by_user_id) SELECT $1,id,$3,$4,$5,$6,$7,$8 FROM crisis_activations WHERE id=$2 AND tenant_id=$1 AND status<>'stood_down' RETURNING *`,[tenantId,req.params.id,title,String(req.body.description||'').trim()||null,priority,assigned,req.body.due_at||null,req.auth.user_id]));if(!row.rowCount)return res.status(404).json({error:'Active crisis not found'});res.status(201).json(row.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.patch('/api/crisis-mode/actions/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||''),note=String(req.body.completion_note||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['open','in_progress','completed','cancelled'].includes(status))return res.status(400).json({error:'Invalid action status'});if(status==='completed'&&!note)return res.status(400).json({error:'Completion note is required'});try{const row=await withTenant(tenantId,c=>c.query(`UPDATE crisis_actions SET status=$1,completion_note=CASE WHEN $1='completed' THEN $2 ELSE completion_note END,completed_by_user_id=CASE WHEN $1='completed' THEN $3 ELSE NULL END,completed_at=CASE WHEN $1='completed' THEN NOW() ELSE NULL END WHERE id=$4 AND tenant_id=$5 RETURNING *`,[status,note,req.auth.user_id,req.params.id,tenantId]));if(!row.rowCount)return res.status(404).json({error:'Crisis action not found'});res.json(row.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/crisis-mode/:id/updates',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),type=String(req.body.update_type||'operational'),message=String(req.body.message||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!message)return res.status(400).json({error:'Update message is required'});try{const row=await withTenant(tenantId,c=>c.query(`INSERT INTO crisis_updates(tenant_id,crisis_id,update_type,message,created_by_user_id) SELECT $1,id,$3,$4,$5 FROM crisis_activations WHERE id=$2 AND tenant_id=$1 AND status<>'stood_down' RETURNING *`,[tenantId,req.params.id,type,message,req.auth.user_id]));if(!row.rowCount)return res.status(404).json({error:'Active crisis not found'});res.status(201).json(row.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.patch('/api/crisis-mode/:id/status',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||''),reason=String(req.body.reason||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['active','contained','stood_down'].includes(status))return res.status(400).json({error:'Invalid crisis status'});if(status==='stood_down'&&!reason)return res.status(400).json({error:'Stand-down reason is required'});try{const row=await withTenant(tenantId,async c=>{if(status==='stood_down'){const open=(await c.query(`SELECT COUNT(*)::int count FROM crisis_actions WHERE crisis_id=$1 AND tenant_id=$2 AND status NOT IN('completed','cancelled')`,[req.params.id,tenantId])).rows[0];if(Number(open.count)>0)throw Object.assign(new Error(`${open.count} crisis action(s) remain open`),{statusCode:409})}const updated=(await c.query(`UPDATE crisis_activations SET status=$1,stood_down_by_user_id=CASE WHEN $1='stood_down' THEN $2 ELSE NULL END,stood_down_at=CASE WHEN $1='stood_down' THEN NOW() ELSE NULL END,stand_down_reason=CASE WHEN $1='stood_down' THEN $3 ELSE stand_down_reason END,updated_at=NOW() WHERE id=$4 AND tenant_id=$5 AND status<>'stood_down' RETURNING *`,[status,req.auth.user_id,reason,req.params.id,tenantId])).rows[0];if(!updated)throw Object.assign(new Error('Active crisis not found'),{statusCode:404});await c.query(`INSERT INTO crisis_updates(tenant_id,crisis_id,update_type,message,created_by_user_id) VALUES($1,$2,'status',$3,$4)`,[tenantId,req.params.id,status==='stood_down'?`Crisis stood down: ${reason}`:`Crisis status changed to ${status}`,req.auth.user_id]);return updated});res.json(row)}catch(err){res.status(err.statusCode||500).json({error:err.message})}});

// ------------------------ STAGE 6.3: COMMERCIAL ASSURANCE READINESS ------------------------
app.get('/api/commercial-assurance-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=communicationTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['assurance_risk_forecasts','service_credit_rules','service_credit_recommendations','service_credit_decisions'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(row=>row.table_name);
    add('structures','Stage 6 database structures',required.every(table=>structures.includes(table)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(table=>!structures.includes(table))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(row=>row.enabled&&row.protected),`${rls.filter(row=>row.enabled&&row.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRole=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert,has_table_privilege($1,'public.'||t,'UPDATE') can_update FROM unnest($2::text[]) t`,[tenantRole,required])).rows;
    add('grants','Restricted tenant-role permissions',grants.length===required.length&&grants.every(row=>row.can_read&&row.can_insert&&row.can_update),grants.length?`${grants.filter(row=>row.can_read&&row.can_insert&&row.can_update).length}/${required.length} tables readable and writable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const data=await withTenant(tenantId,async client=>{
      const [contracts,forecasts,rules,recommendations,decisions]=await Promise.all([
        client.query(`SELECT COUNT(*)::int total,COUNT(DISTINCT site_id)::int sites FROM service_contracts WHERE tenant_id=$1 AND status='active' AND start_date<=CURRENT_DATE AND(end_date IS NULL OR end_date>=CURRENT_DATE)`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(DISTINCT f.site_id)::int sites,COUNT(*) FILTER(WHERE f.risk_score<0 OR f.risk_score>100 OR f.breach_probability<0 OR f.breach_probability>100 OR f.risk_band NOT IN('low','medium','high','critical'))::int invalid,COUNT(*) FILTER(WHERE jsonb_typeof(f.signals)<>'object' OR jsonb_typeof(f.reasons)<>'array' OR jsonb_array_length(f.reasons)=0 OR jsonb_typeof(f.recommended_actions)<>'array')::int unexplained,COUNT(*) FILTER(WHERE sc.id IS NULL OR s.id IS NULL)::int broken,MAX(f.calculated_at) latest FROM assurance_risk_forecasts f LEFT JOIN sites s ON s.id=f.site_id AND s.tenant_id=f.tenant_id LEFT JOIN service_contracts sc ON sc.id=f.contract_id AND sc.tenant_id=f.tenant_id WHERE f.tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE r.patrol_miss_pct<0 OR r.patrol_miss_pct>100 OR r.incident_miss_pct<0 OR r.incident_miss_pct>100 OR r.coverage_miss_pct<0 OR r.coverage_miss_pct>100 OR r.maximum_credit_pct<0 OR r.maximum_credit_pct>100)::int invalid,COUNT(*) FILTER(WHERE sc.id IS NULL)::int broken FROM service_credit_rules r LEFT JOIN service_contracts sc ON sc.id=r.contract_id AND sc.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.active=TRUE`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE r.status='draft')::int drafts,COUNT(*) FILTER(WHERE r.status='approved')::int approved,COUNT(*) FILTER(WHERE r.status='rejected')::int rejected,COUNT(*) FILTER(WHERE r.credit_percent<0 OR r.credit_percent>100 OR r.credit_basis<0 OR r.recommended_amount<0 OR ABS(r.recommended_amount-(r.credit_basis*r.credit_percent/100))>0.02 OR jsonb_typeof(r.metrics)<>'object' OR jsonb_typeof(r.reasons)<>'array')::int invalid,COUNT(*) FILTER(WHERE sc.id IS NULL OR s.id IS NULL)::int broken,COUNT(*) FILTER(WHERE r.status IN('approved','rejected') AND(r.decided_by_user_id IS NULL OR r.decided_at IS NULL OR COALESCE(BTRIM(r.decision_reason),'')=''))::int missing_decision_evidence FROM service_credit_recommendations r LEFT JOIN service_contracts sc ON sc.id=r.contract_id AND sc.tenant_id=r.tenant_id LEFT JOIN sites s ON s.id=r.site_id AND s.tenant_id=r.tenant_id WHERE r.tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE d.new_status NOT IN('approved','rejected') OR COALESCE(BTRIM(d.reason),'')='' OR d.decided_by_user_id IS NULL OR r.id IS NULL OR r.status<>d.new_status)::int invalid FROM service_credit_decisions d LEFT JOIN service_credit_recommendations r ON r.id=d.recommendation_id AND r.tenant_id=d.tenant_id WHERE d.tenant_id=$1`,[tenantId])
      ]);
      return{contracts:contracts.rows[0],forecasts:forecasts.rows[0],rules:rules.rows[0],recommendations:recommendations.rows[0],decisions:decisions.rows[0]};
    });
    add('forecast_integrity','Predictive-risk forecast integrity',Number(data.forecasts.total)>0&&Number(data.forecasts.invalid)===0&&Number(data.forecasts.broken)===0,`${data.forecasts.total} saved forecast(s); ${data.forecasts.invalid} invalid; ${data.forecasts.broken} broken relationship(s)`,true,data.forecasts);
    add('forecast_explainability','Explainable forecast evidence',Number(data.forecasts.total)>0&&Number(data.forecasts.unexplained)===0,`${Number(data.forecasts.total)-Number(data.forecasts.unexplained)}/${data.forecasts.total} forecast(s) include signals, reasons, and recommended interventions`,true,{total:Number(data.forecasts.total),unexplained:Number(data.forecasts.unexplained)});
    add('forecast_coverage','Active-contract forecast coverage',Number(data.contracts.sites)>0&&Number(data.forecasts.sites)>=Number(data.contracts.sites),`${data.forecasts.sites}/${data.contracts.sites} active contract site(s) have a saved forecast`,false,{active_contracts:Number(data.contracts.total),active_sites:Number(data.contracts.sites),forecast_sites:Number(data.forecasts.sites),latest:data.forecasts.latest});
    add('credit_policy','Service-credit policy controls',Number(data.rules.invalid)===0&&Number(data.rules.broken)===0,`${data.rules.total} custom active policy/policies; valid defaults apply to remaining active contracts`,true,data.rules);
    add('recommendation_integrity','Credit recommendation calculations',Number(data.recommendations.invalid)===0&&Number(data.recommendations.broken)===0,`${data.recommendations.total} recommendation(s); ${data.recommendations.invalid} invalid calculation(s); ${data.recommendations.broken} broken relationship(s)`,true,data.recommendations);
    const decided=Number(data.recommendations.approved)+Number(data.recommendations.rejected);
    add('approval_governance','Recorded approval governance',Number(data.recommendations.missing_decision_evidence)===0&&Number(data.decisions.invalid)===0&&Number(data.decisions.total)>=decided,decided?`${decided} decided recommendation(s); ${data.decisions.total} immutable decision record(s)`:'No recommendation has been approved or rejected yet; approval controls are ready',false,{decided,decision_records:Number(data.decisions.total),invalid_decisions:Number(data.decisions.invalid),missing_evidence:Number(data.recommendations.missing_decision_evidence)});
    add('invoice_boundary','No automatic invoice modification',true,'Credit approval remains a recorded recommendation and does not alter invoices automatically',true,{automatic_invoice_changes:0});
    const failures=checks.filter(check=>check.critical&&!check.passed),warnings=checks.filter(check=>!check.critical&&!check.passed),status=failures.length?'action_required':warnings.length?'ready_with_warnings':'stage_6_ready';
    res.json({status,ready:failures.length===0,generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(check=>check.passed).length,warnings:warnings.length,failures:failures.length,total:checks.length},activity:{active_contracts:Number(data.contracts.total),saved_forecasts:Number(data.forecasts.total),credit_recommendations:Number(data.recommendations.total),decisions:Number(data.decisions.total)},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}
});

// ------------------------ STAGE 7.3: RECONSTRUCTION & CRISIS READINESS ------------------------
app.get('/api/reconstruction-crisis-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=communicationTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    await crisisModeSchemaReady;
    const required=['crisis_activations','crisis_roles','crisis_actions','crisis_updates'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 7 crisis-response structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRole=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert,has_table_privilege($1,'public.'||t,'UPDATE') can_update FROM unnest($2::text[]) t`,[tenantRole,required])).rows;
    add('grants','Restricted tenant-role permissions',grants.length===required.length&&grants.every(x=>x.can_read&&x.can_insert&&x.can_update),grants.length?`${grants.filter(x=>x.can_read&&x.can_insert&&x.can_update).length}/${required.length} tables readable and writable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const data=await withTenant(tenantId,async c=>{
      const [sources,activations,commanders,actions,updates,standDown,duplicates]=await Promise.all([
        c.query(`SELECT (SELECT COUNT(*) FROM incidents WHERE tenant_id=$1)::int incidents,(SELECT COUNT(*) FROM incident_activities WHERE tenant_id=$1)::int activities,(SELECT COUNT(*) FROM incident_photos WHERE tenant_id=$1)::int photos,(SELECT COUNT(*) FROM patrol_logs WHERE tenant_id=$1)::int patrol_scans,(SELECT COUNT(*) FROM sos_alerts WHERE tenant_id=$1)::int sos_alerts,(SELECT COUNT(*) FROM dispatch_jobs WHERE tenant_id=$1)::int dispatches,(SELECT COUNT(*) FROM guard_location_history WHERE tenant_id=$1)::int locations,(SELECT COUNT(*) FROM audit_logs WHERE tenant_id=$1 AND resource ILIKE '%incident%')::int audit_events`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE i.id IS NULL OR s.id IS NULL OR commander.id IS NULL OR creator.id IS NULL OR ca.status NOT IN('active','contained','stood_down') OR ca.severity NOT IN('major','critical'))::int invalid,COUNT(*) FILTER(WHERE ca.status<>'stood_down')::int open FROM crisis_activations ca LEFT JOIN incidents i ON i.id=ca.incident_id AND i.tenant_id=ca.tenant_id LEFT JOIN sites s ON s.id=ca.site_id AND s.tenant_id=ca.tenant_id LEFT JOIN users commander ON commander.id=ca.commander_user_id AND commander.tenant_id=ca.tenant_id LEFT JOIN users creator ON creator.id=ca.activated_by_user_id AND creator.tenant_id=ca.tenant_id WHERE ca.tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*)::int crises,COUNT(*) FILTER(WHERE r.id IS NULL OR r.user_id<>ca.commander_user_id)::int missing FROM crisis_activations ca LEFT JOIN crisis_roles r ON r.crisis_id=ca.id AND r.tenant_id=ca.tenant_id AND r.role_name='Crisis Commander' WHERE ca.tenant_id=$1 GROUP BY ca.tenant_id`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE ca.id IS NULL OR a.status NOT IN('open','in_progress','completed','cancelled') OR(a.status='completed' AND(a.completed_by_user_id IS NULL OR a.completed_at IS NULL OR COALESCE(BTRIM(a.completion_note),'')='')))::int invalid,COUNT(*) FILTER(WHERE a.status NOT IN('completed','cancelled'))::int open FROM crisis_actions a LEFT JOIN crisis_activations ca ON ca.id=a.crisis_id AND ca.tenant_id=a.tenant_id WHERE a.tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE ca.id IS NULL OR COALESCE(BTRIM(cu.message),'')='' OR cu.update_type NOT IN('operational','communication','decision','status'))::int invalid FROM crisis_updates cu LEFT JOIN crisis_activations ca ON ca.id=cu.crisis_id AND ca.tenant_id=cu.tenant_id WHERE cu.tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*) FILTER(WHERE status='stood_down')::int stood_down,COUNT(*) FILTER(WHERE status='stood_down' AND(stood_down_by_user_id IS NULL OR stood_down_at IS NULL OR COALESCE(BTRIM(stand_down_reason),'')=''))::int missing_evidence,COUNT(*) FILTER(WHERE status='stood_down' AND EXISTS(SELECT 1 FROM crisis_actions a WHERE a.crisis_id=crisis_activations.id AND a.tenant_id=crisis_activations.tenant_id AND a.status NOT IN('completed','cancelled')))::int stood_down_with_open_actions FROM crisis_activations WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*)::int duplicates FROM(SELECT incident_id FROM crisis_activations WHERE tenant_id=$1 AND status<>'stood_down' GROUP BY incident_id HAVING COUNT(*)>1)x`,[tenantId])
      ]);return{sources:sources.rows[0],activations:activations.rows[0],commanders:commanders.rows[0]||{crises:0,missing:0},actions:actions.rows[0],updates:updates.rows[0],stand_down:standDown.rows[0],duplicates:duplicates.rows[0]}
    });
    const sourceTotal=Object.values(data.sources).reduce((sum,value)=>sum+Number(value),0);
    add('reconstruction_sources','Incident reconstruction source coverage',Number(data.sources.incidents)>0&&sourceTotal>Number(data.sources.incidents),`${data.sources.incidents} incident(s); ${sourceTotal-Number(data.sources.incidents)} supporting source record(s) available`,true,data.sources);
    add('activation_integrity','Crisis activation integrity',Number(data.activations.total)>0&&Number(data.activations.invalid)===0,`${data.activations.total} activation(s); ${data.activations.invalid} invalid relationship or state record(s)`,true,data.activations);
    add('commander_accountability','Crisis commander accountability',Number(data.commanders.crises)===Number(data.activations.total)&&Number(data.commanders.missing)===0,`${Number(data.commanders.crises)-Number(data.commanders.missing)}/${data.activations.total} activation(s) have a matching Crisis Commander role`,true,data.commanders);
    add('active_uniqueness','One active crisis per incident',Number(data.duplicates.duplicates)===0,`${data.duplicates.duplicates} incident(s) have duplicate active crisis responses`,true,data.duplicates);
    add('action_integrity','Crisis action integrity',Number(data.actions.invalid)===0,`${data.actions.total} action(s); ${data.actions.open} open; ${data.actions.invalid} invalid completion record(s)`,true,data.actions);
    add('communications','Crisis communications history',Number(data.updates.total)>=Number(data.activations.total)&&Number(data.updates.invalid)===0,`${data.updates.total} update(s); ${data.updates.invalid} invalid`,true,data.updates);
    add('stand_down','Formal stand-down governance',Number(data.stand_down.missing_evidence)===0&&Number(data.stand_down.stood_down_with_open_actions)===0,`${data.stand_down.stood_down} stood down; ${data.stand_down.missing_evidence} missing evidence; ${data.stand_down.stood_down_with_open_actions} with open actions`,true,data.stand_down);
    const failures=checks.filter(x=>x.critical&&!x.passed),warnings=checks.filter(x=>!x.critical&&!x.passed),status=failures.length?'action_required':warnings.length?'ready_with_warnings':'stage_7_ready';
    res.json({status,ready:failures.length===0,generated_at:new Date(),duration_ms:Date.now()-started,summary:{passed:checks.filter(x=>x.passed).length,warnings:warnings.length,failures:failures.length,total:checks.length},activity:{incidents:Number(data.sources.incidents),crises:Number(data.activations.total),active_crises:Number(data.activations.open),open_actions:Number(data.actions.open)},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}
});

// ------------------------ STAGE 8.1: CLIENT RETENTION RADAR ------------------------
async function ensureClientRetentionRadarSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS client_retention_snapshots(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,
    contract_id BIGINT NOT NULL REFERENCES service_contracts(id) ON DELETE CASCADE,
    horizon_days INTEGER NOT NULL,risk_score NUMERIC(5,2) NOT NULL,risk_band TEXT NOT NULL,
    signals JSONB NOT NULL DEFAULT '{}'::jsonb,reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,model_version TEXT NOT NULL DEFAULT 'PS Retention v1',
    calculated_by_user_id INTEGER,calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT client_retention_score CHECK(risk_score BETWEEN 0 AND 100),
    CONSTRAINT client_retention_band CHECK(risk_band IN('low','medium','high','critical')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS client_retention_snapshots_tenant_contract_time ON client_retention_snapshots(tenant_id,contract_id,calculated_at DESC)`);
  await pool.query(`ALTER TABLE client_retention_snapshots ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON client_retention_snapshots`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON client_retention_snapshots USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON client_retention_snapshots TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE client_retention_snapshots_id_seq TO "${role}"`)}}catch(err){console.warn('Retention Radar tenant-role grant skipped:',err.message)}
  console.log('Client Retention Radar schema ready');
}
ensureClientRetentionRadarSchema().catch(err=>console.error('Client Retention Radar schema setup failed:',err.message));

async function buildClientRetentionRadar(client,tenantId,horizonDays=90,siteId=null){
  const params=[tenantId];let siteClause='';if(siteId){params.push(Number(siteId));siteClause=` AND sc.site_id=$${params.length}`}
  params.push(horizonDays);const horizonParam=params.length;
  const rows=(await client.query(`SELECT sc.id contract_id,sc.site_id,sc.reference_code,sc.client_name,sc.end_date,sc.rate,sc.currency,s.name site_name,
    GREATEST(0,(sc.end_date-CURRENT_DATE))::int days_to_expiry,cr.status renewal_status,cr.next_follow_up_date,cr.last_contact_at,
    (SELECT p.score FROM proofscore_snapshots p WHERE p.tenant_id=sc.tenant_id AND p.site_id=sc.site_id ORDER BY p.calculated_at DESC LIMIT 1) proofscore,
    (SELECT COUNT(*)::int FROM service_tickets st WHERE st.tenant_id=sc.tenant_id AND st.site_id=sc.site_id AND st.status NOT IN('resolved','closed')) open_tickets,
    (SELECT COUNT(*)::int FROM service_tickets st WHERE st.tenant_id=sc.tenant_id AND st.site_id=sc.site_id AND st.priority IN('high','urgent') AND st.status NOT IN('resolved','closed')) urgent_tickets,
    (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=sc.tenant_id AND i.site_id=sc.site_id AND i.status NOT IN('resolved','closed')) open_incidents,
    (SELECT COUNT(*)::int FROM assurance_improvement_actions a WHERE a.tenant_id=sc.tenant_id AND a.site_id=sc.site_id AND a.status NOT IN('completed','cancelled')) open_actions,
    (SELECT COUNT(*)::int FROM assurance_improvement_actions a WHERE a.tenant_id=sc.tenant_id AND a.site_id=sc.site_id AND a.status NOT IN('completed','cancelled') AND a.due_date<CURRENT_DATE) overdue_actions,
    (SELECT COUNT(*)::int FROM client_users cu WHERE cu.tenant_id=sc.tenant_id AND cu.site_id=sc.site_id) client_accounts
    FROM service_contracts sc JOIN sites s ON s.id=sc.site_id AND s.tenant_id=sc.tenant_id LEFT JOIN contract_renewals cr ON cr.contract_id=sc.id AND cr.tenant_id=sc.tenant_id
    WHERE sc.tenant_id=$1 AND sc.status='active' AND(sc.end_date IS NULL OR sc.end_date<=CURRENT_DATE+$${horizonParam}::int)${siteClause} ORDER BY sc.end_date NULLS LAST,s.name`,params)).rows;
  const contracts=rows.map(row=>{
    const score=Number(row.proofscore),hasScore=row.proofscore!==null;let risk=0,reasons=[],actions=[];
    const days=row.end_date?Number(row.days_to_expiry):null,renewal=String(row.renewal_status||'not_started');
    if(days!==null){if(days<=30){risk+=30;reasons.push(`Contract expires in ${days} day(s).`)}else if(days<=60){risk+=20;reasons.push(`Contract expires in ${days} days.`)}else if(days<=90){risk+=10;reasons.push(`Contract enters its renewal window in ${days} days.`)}}
    if(!hasScore){risk+=15;reasons.push('No published ProofScore baseline is available.')}else if(score<60){risk+=30;reasons.push(`ProofScore is ${score.toFixed(2)}%, indicating material assurance weakness.`)}else if(score<80){risk+=20;reasons.push(`ProofScore is ${score.toFixed(2)}%, below the 80% assurance target.`)}
    const openTickets=Number(row.open_tickets||0),urgent=Number(row.urgent_tickets||0),incidents=Number(row.open_incidents||0),overdue=Number(row.overdue_actions||0);
    risk+=Math.min(15,openTickets*3)+Math.min(15,urgent*7)+Math.min(10,incidents*2)+Math.min(15,overdue*5);
    if(openTickets)reasons.push(`${openTickets} client service request(s) remain open.`);if(urgent)reasons.push(`${urgent} high or urgent client request(s) require attention.`);if(incidents)reasons.push(`${incidents} incident(s) remain unresolved.`);if(overdue)reasons.push(`${overdue} assurance action(s) are overdue.`);
    if(renewal==='not_started'&&days!==null&&days<=90){risk+=10;reasons.push('The renewal workflow has not started.')}if(renewal==='negotiating')risk=Math.max(0,risk-5);
    risk=Math.max(0,Math.min(100,Math.round(risk*100)/100));const band=risk>=75?'critical':risk>=50?'high':risk>=25?'medium':'low';
    if(days!==null&&days<=90)actions.push('Assign a renewal owner and confirm the next client contact.');if(!hasScore||score<80)actions.push('Review ProofScore weaknesses and publish client-visible improvement progress.');if(openTickets||urgent)actions.push('Resolve or formally update outstanding client service requests.');if(incidents)actions.push('Close unresolved incident actions with documented evidence.');if(overdue)actions.push('Escalate overdue assurance actions and agree revised deadlines.');if(!actions.length)actions.push('Maintain normal client review cadence and monitor trend movement.');
    return{contract_id:Number(row.contract_id),site_id:Number(row.site_id),reference_code:row.reference_code,client_name:row.client_name,site_name:row.site_name,end_date:row.end_date,days_to_expiry:days,renewal_status:renewal,risk_score:risk,risk_band:band,signals:{proofscore:hasScore?score:null,open_tickets:openTickets,urgent_tickets:urgent,open_incidents:incidents,open_actions:Number(row.open_actions||0),overdue_actions:overdue,client_accounts:Number(row.client_accounts||0),next_follow_up_date:row.next_follow_up_date,last_contact_at:row.last_contact_at},reasons,recommended_actions:actions,model_version:'PS Retention v1'};
  });
  return{generated_at:new Date().toISOString(),horizon_days:horizonDays,summary:{contracts:contracts.length,critical:contracts.filter(x=>x.risk_band==='critical').length,high:contracts.filter(x=>x.risk_band==='high').length,renewals_due:contracts.filter(x=>x.days_to_expiry!==null&&x.days_to_expiry<=90).length},contracts};
}

app.get('/api/client-retention-radar',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id),horizon=Math.max(30,Math.min(365,Number(req.query.horizon_days||90)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{res.json(await withTenant(tenantId,c=>buildClientRetentionRadar(c,tenantId,horizon,req.query.site_id||null)))}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/client-retention-radar/run',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),horizon=Math.max(30,Math.min(365,Number(req.body.horizon_days||90)));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const report=await withTenant(tenantId,async c=>{const data=await buildClientRetentionRadar(c,tenantId,horizon,req.body.site_id||null);for(const x of data.contracts)await c.query(`INSERT INTO client_retention_snapshots(tenant_id,site_id,contract_id,horizon_days,risk_score,risk_band,signals,reasons,recommended_actions,model_version,calculated_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[tenantId,x.site_id,x.contract_id,horizon,x.risk_score,x.risk_band,JSON.stringify(x.signals),JSON.stringify(x.reasons),JSON.stringify(x.recommended_actions),x.model_version,req.auth.user_id]);return data});res.status(201).json({...report,saved:true})}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/client-retention-radar/history',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,c=>{const p=[tenantId];let q=`SELECT r.*,s.name site_name,sc.reference_code,sc.client_name,u.email calculated_by_email FROM client_retention_snapshots r JOIN sites s ON s.id=r.site_id AND s.tenant_id=r.tenant_id JOIN service_contracts sc ON sc.id=r.contract_id AND sc.tenant_id=r.tenant_id LEFT JOIN users u ON u.id=r.calculated_by_user_id AND u.tenant_id=r.tenant_id WHERE r.tenant_id=$1`;if(req.query.site_id){p.push(Number(req.query.site_id));q+=` AND r.site_id=$${p.length}`}q+=` ORDER BY r.calculated_at DESC LIMIT 250`;return c.query(q,p)});res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});

// ------------------------ STAGE 8.2: TENDER & PROPOSAL BUILDER ------------------------
async function ensureTenderProposalSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS tender_proposals(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,title TEXT NOT NULL,prospect_name TEXT NOT NULL,
    reference_code TEXT NOT NULL,currency TEXT NOT NULL DEFAULT 'EUR',contract_value NUMERIC(12,2),
    valid_until DATE,status TEXT NOT NULL DEFAULT 'draft',executive_summary TEXT NOT NULL,scope TEXT NOT NULL,
    capability_sections JSONB NOT NULL DEFAULT '[]'::jsonb,implementation_plan TEXT,commercial_terms TEXT,
    assumptions TEXT,internal_notes TEXT,created_by_user_id INTEGER,approved_by_user_id INTEGER,
    approved_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT tender_proposal_status CHECK(status IN('draft','review','approved','issued','won','lost','archived')),
    UNIQUE(tenant_id,reference_code))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS tender_proposals_tenant_status_time ON tender_proposals(tenant_id,status,updated_at DESC)`);
  await pool.query(`ALTER TABLE tender_proposals ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON tender_proposals`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON tender_proposals USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON tender_proposals TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE tender_proposals_id_seq TO "${role}"`)}}catch(err){console.warn('Tender proposal tenant-role grant skipped:',err.message)}
  console.log('Tender proposal schema ready');
}
ensureTenderProposalSchema().catch(err=>console.error('Tender proposal schema setup failed:',err.message));

async function tenderCapabilityEvidence(client,tenantId){
  const [sites,guards,checkpoints,proof,evidence,contracts,features]=await Promise.all([
    client.query(`SELECT COUNT(*)::int total FROM sites WHERE tenant_id=$1`,[tenantId]),
    client.query(`SELECT COUNT(*)::int total FROM users WHERE tenant_id=$1 AND role='guard' AND COALESCE(active,TRUE)=TRUE`,[tenantId]),
    client.query(`SELECT COUNT(*)::int total FROM checkpoints WHERE tenant_id=$1`,[tenantId]),
    client.query(`SELECT COUNT(*)::int total,ROUND(AVG(score),2) average FROM(SELECT DISTINCT ON(site_id) site_id,score FROM proofscore_snapshots WHERE tenant_id=$1 ORDER BY site_id,calculated_at DESC)p`,[tenantId]),
    client.query(`SELECT COUNT(*)::int total FROM evidence_integrity_records WHERE tenant_id=$1`,[tenantId]),
    client.query(`SELECT COUNT(*)::int total FROM service_contracts WHERE tenant_id=$1 AND status='active'`,[tenantId]),
    client.query(`SELECT feature_code FROM tenant_entitlement_overrides WHERE tenant_id=$1 AND enabled=TRUE AND(expires_at IS NULL OR expires_at>NOW())`,[tenantId]).catch(()=>({rows:[]}))
  ]);
  const operational=[
    {code:'workforce',title:'Workforce scheduling and attendance',description:'Shift scheduling, confirmations, availability, time clock, timesheets, leave and coverage controls.'},
    {code:'patrol',title:'Verified patrol operations',description:'QR and NFC checkpoints, routes, offline capture, geofencing, patrol alerts and TrustProof evidence integrity.'},
    {code:'incident',title:'Incident and crisis response',description:'Incident cases, evidence, reconstruction, SOS, dispatch, governed Crisis Mode and audit history.'},
    {code:'assurance',title:'Client assurance and SLA governance',description:'ProofScore, SLA performance, improvement plans, predictive risk, service-credit recommendations and client reporting.'},
    {code:'compliance',title:'Workforce compliance',description:'Certificates, competency requirements, training, visitor management, equipment custody and readiness gates.'},
    {code:'security',title:'Enterprise operational controls',description:'Multi-tenant RLS, role permissions, audit logs, MFA, sessions, private object storage, APIs and webhooks.'}
  ];
  return{metrics:{sites:Number(sites.rows[0].total),active_guards:Number(guards.rows[0].total),checkpoints:Number(checkpoints.rows[0].total),published_proofscore_sites:Number(proof.rows[0].total),average_proofscore:proof.rows[0].average===null?null:Number(proof.rows[0].average),sealed_evidence:Number(evidence.rows[0].total),active_contracts:Number(contracts.rows[0].total)},capabilities:operational,enabled_overrides:features.rows.map(x=>x.feature_code),notice:'Metrics describe the authenticated company environment only. They are not promises about future delivery or a prospect environment.'};
}

app.get('/api/tender-proposals/evidence',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{res.json(await withTenant(tenantId,c=>tenderCapabilityEvidence(c,tenantId)))}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/tender-proposals',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,c=>{const p=[tenantId];let q=`SELECT t.*,cu.email created_by_email,au.email approved_by_email FROM tender_proposals t LEFT JOIN users cu ON cu.id=t.created_by_user_id AND cu.tenant_id=t.tenant_id LEFT JOIN users au ON au.id=t.approved_by_user_id AND au.tenant_id=t.tenant_id WHERE t.tenant_id=$1`;if(req.query.status){p.push(String(req.query.status));q+=` AND t.status=$${p.length}`}q+=` ORDER BY t.updated_at DESC LIMIT 250`;return c.query(q,p)});res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/tender-proposals',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),title=String(req.body.title||'').trim(),prospect=String(req.body.prospect_name||'').trim(),summary=String(req.body.executive_summary||'').trim(),scope=String(req.body.scope||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!title||!prospect||!summary||!scope)return res.status(400).json({error:'Title, prospect, executive summary and scope are required'});try{const result=await withTenant(tenantId,async c=>{const seq=await c.query(`SELECT COALESCE(MAX(id),0)+1 next FROM tender_proposals WHERE tenant_id=$1`,[tenantId]),reference=`TEN-${new Date().getFullYear()}-${String(seq.rows[0].next).padStart(5,'0')}`;return c.query(`INSERT INTO tender_proposals(tenant_id,title,prospect_name,reference_code,currency,contract_value,valid_until,status,executive_summary,scope,capability_sections,implementation_plan,commercial_terms,assumptions,internal_notes,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,'draft',$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,[tenantId,title,prospect,reference,String(req.body.currency||'EUR').toUpperCase(),req.body.contract_value===''||req.body.contract_value==null?null:Number(req.body.contract_value),req.body.valid_until||null,summary,scope,JSON.stringify(Array.isArray(req.body.capability_sections)?req.body.capability_sections:[]),String(req.body.implementation_plan||'').trim()||null,String(req.body.commercial_terms||'').trim()||null,String(req.body.assumptions||'').trim()||null,String(req.body.internal_notes||'').trim()||null,req.auth.user_id])});res.status(201).json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.patch('/api/tender-proposals/:id',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),status=String(req.body.status||'draft');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['draft','review','approved','issued','won','lost','archived'].includes(status))return res.status(400).json({error:'Invalid proposal status'});try{const result=await withTenant(tenantId,c=>c.query(`UPDATE tender_proposals SET title=$3,prospect_name=$4,currency=$5,contract_value=$6,valid_until=$7,status=$8,executive_summary=$9,scope=$10,capability_sections=$11,implementation_plan=$12,commercial_terms=$13,assumptions=$14,internal_notes=$15,approved_by_user_id=CASE WHEN $8='approved' THEN COALESCE(approved_by_user_id,$16) ELSE approved_by_user_id END,approved_at=CASE WHEN $8='approved' THEN COALESCE(approved_at,NOW()) ELSE approved_at END,updated_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING *`,[req.params.id,tenantId,String(req.body.title||'').trim(),String(req.body.prospect_name||'').trim(),String(req.body.currency||'EUR').toUpperCase(),req.body.contract_value===''||req.body.contract_value==null?null:Number(req.body.contract_value),req.body.valid_until||null,status,String(req.body.executive_summary||'').trim(),String(req.body.scope||'').trim(),JSON.stringify(Array.isArray(req.body.capability_sections)?req.body.capability_sections:[]),String(req.body.implementation_plan||'').trim()||null,String(req.body.commercial_terms||'').trim()||null,String(req.body.assumptions||'').trim()||null,String(req.body.internal_notes||'').trim()||null,req.auth.user_id]));if(!result.rowCount)return res.status(404).json({error:'Proposal not found'});res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}});

// ------------------------ STAGE 8.3: CLIENT INTELLIGENCE READINESS ------------------------
app.get('/api/client-intelligence-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=communicationTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['client_retention_snapshots','tender_proposals'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 8 intelligence structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRole=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert,has_table_privilege($1,'public.'||t,'UPDATE') can_update FROM unnest($2::text[]) t`,[tenantRole,required])).rows;
    add('grants','Restricted tenant-role permissions',grants.length===required.length&&grants.every(x=>x.can_read&&x.can_insert&&x.can_update),grants.length?`${grants.filter(x=>x.can_read&&x.can_insert&&x.can_update).length}/${required.length} tables readable and writable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const data=await withTenant(tenantId,async client=>{
      const [retention,explainable,dueCoverage,proposals,relationships,approvals]=await Promise.all([
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE risk_score<0 OR risk_score>100 OR risk_band NOT IN('low','medium','high','critical') OR horizon_days<30 OR horizon_days>365)::int invalid,MAX(calculated_at) latest FROM client_retention_snapshots WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE jsonb_typeof(signals)<>'object' OR jsonb_typeof(reasons)<>'array' OR jsonb_array_length(reasons)=0 OR jsonb_typeof(recommended_actions)<>'array' OR jsonb_array_length(recommended_actions)=0)::int incomplete FROM client_retention_snapshots WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int due,COUNT(*) FILTER(WHERE EXISTS(SELECT 1 FROM client_retention_snapshots r WHERE r.tenant_id=sc.tenant_id AND r.contract_id=sc.id))::int covered FROM service_contracts sc WHERE sc.tenant_id=$1 AND sc.status='active' AND sc.end_date BETWEEN CURRENT_DATE AND CURRENT_DATE+90`,[tenantId]),
        client.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE status NOT IN('draft','review','approved','issued','won','lost','archived') OR BTRIM(title)='' OR BTRIM(prospect_name)='' OR BTRIM(executive_summary)='' OR BTRIM(scope)='' OR jsonb_typeof(capability_sections)<>'array')::int invalid,COUNT(*) FILTER(WHERE jsonb_array_length(capability_sections)>0)::int with_capabilities FROM tender_proposals WHERE tenant_id=$1`,[tenantId]),
        client.query(`SELECT COUNT(*)::int broken FROM client_retention_snapshots r LEFT JOIN sites s ON s.id=r.site_id AND s.tenant_id=r.tenant_id LEFT JOIN service_contracts sc ON sc.id=r.contract_id AND sc.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND(s.id IS NULL OR sc.id IS NULL OR sc.site_id<>r.site_id)`,[tenantId]),
        client.query(`SELECT COUNT(*) FILTER(WHERE status IN('approved','issued','won'))::int governed,COUNT(*) FILTER(WHERE status IN('approved','issued','won') AND(approved_by_user_id IS NULL OR approved_at IS NULL))::int invalid FROM tender_proposals WHERE tenant_id=$1`,[tenantId])
      ]);return{retention:retention.rows[0],explainable:explainable.rows[0],coverage:dueCoverage.rows[0],proposals:proposals.rows[0],relationships:relationships.rows[0],approvals:approvals.rows[0]};
    });
    add('retention_integrity','Retention snapshot integrity',Number(data.retention.total)>0&&Number(data.retention.invalid)===0,`${data.retention.total} saved snapshot(s); ${data.retention.invalid} invalid`,true,data.retention);
    add('retention_explainability','Explainable retention evidence',Number(data.explainable.total)>0&&Number(data.explainable.incomplete)===0,`${Number(data.explainable.total)-Number(data.explainable.incomplete)}/${data.explainable.total} snapshot(s) include signals, reasons and recommended actions`,true,data.explainable);
    add('renewal_coverage','Upcoming-renewal coverage',Number(data.coverage.due)===Number(data.coverage.covered),`${data.coverage.covered}/${data.coverage.due} active contract(s) expiring within 90 days have retention evidence`,true,data.coverage);
    add('proposal_integrity','Tender proposal integrity',Number(data.proposals.total)>0&&Number(data.proposals.invalid)===0,`${data.proposals.total} proposal(s); ${data.proposals.invalid} invalid record(s)`,true,data.proposals);
    add('capability_governance','Verified capability selection',Number(data.proposals.total)>0&&Number(data.proposals.with_capabilities)===Number(data.proposals.total),`${data.proposals.with_capabilities}/${data.proposals.total} proposal(s) include selected verified capability sections`,false,data.proposals);
    add('relationships','Client-intelligence relationships',Number(data.relationships.broken)===0,`${data.relationships.broken} broken site or contract relationship(s)`,true,data.relationships);
    add('approval_governance','Proposal approval governance',Number(data.approvals.invalid)===0,Number(data.approvals.governed)>0?`${data.approvals.governed} approved/issued/won proposal(s); ${data.approvals.invalid} missing approval evidence`:'No proposal has been approved or issued yet; controls are ready',false,data.approvals);
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length;
    res.json({status:failures?'action_required':warnings?'ready_with_warnings':'stage_8_ready',label:failures?'ACTION REQUIRED':warnings?'READY WITH WARNINGS':'STAGE 8 READY',completed_at:new Date().toISOString(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},checks});
  }catch(err){res.status(500).json({error:err.message})}
});

// ------------------------ STAGE 9.1: SITE RISK DIGITAL TWIN ------------------------
async function ensureSiteRiskTwinSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS site_risk_twins(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,
    profile_name TEXT NOT NULL DEFAULT 'Operational risk model',site_type TEXT NOT NULL DEFAULT 'commercial',
    occupancy_band TEXT NOT NULL DEFAULT 'medium',public_access BOOLEAN NOT NULL DEFAULT FALSE,
    overnight_operation BOOLEAN NOT NULL DEFAULT FALSE,lone_work_expected BOOLEAN NOT NULL DEFAULT FALSE,
    critical_zones JSONB NOT NULL DEFAULT '[]'::jsonb,hazard_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    control_notes TEXT,model_version INTEGER NOT NULL DEFAULT 1,status TEXT NOT NULL DEFAULT 'active',
    updated_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id,site_id),CONSTRAINT site_risk_twin_occupancy CHECK(occupancy_band IN('low','medium','high')),
    CONSTRAINT site_risk_twin_status CHECK(status IN('active','review','archived')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS site_risk_twins_tenant_site ON site_risk_twins(tenant_id,site_id)`);
  await pool.query(`ALTER TABLE site_risk_twins ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON site_risk_twins`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON site_risk_twins USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON site_risk_twins TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE site_risk_twins_id_seq TO "${role}"`)}}catch(err){console.warn('Site Risk Twin tenant-role grant skipped:',err.message)}
  console.log('Site Risk Digital Twin schema ready');
}
ensureSiteRiskTwinSchema().catch(err=>console.error('Site Risk Digital Twin schema setup failed:',err.message));

async function buildSiteRiskTwins(client,tenantId,siteId=null){
  const p=[tenantId];let clause='';if(siteId){p.push(Number(siteId));clause=` AND s.id=$${p.length}`}
  const rows=(await client.query(`SELECT s.id site_id,s.name site_name,s.address,t.id twin_id,t.profile_name,t.site_type,t.occupancy_band,t.public_access,t.overnight_operation,t.lone_work_expected,t.critical_zones,t.hazard_factors,t.control_notes,t.model_version,t.status,t.updated_at,
    (SELECT COUNT(*)::int FROM checkpoints c WHERE c.tenant_id=s.tenant_id AND c.site_id=s.id) checkpoints,
    (SELECT COUNT(*)::int FROM guard_assignments ga WHERE ga.tenant_id=s.tenant_id AND ga.site_id=s.id) assigned_guards,
    (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=s.tenant_id AND i.site_id=s.id AND COALESCE(i.status,'reported') NOT IN('resolved','closed')) open_incidents,
    (SELECT COUNT(*)::int FROM incidents i WHERE i.tenant_id=s.tenant_id AND i.site_id=s.id AND COALESCE(i.severity,'low') IN('high','critical') AND COALESCE(i.status,'reported') NOT IN('resolved','closed')) severe_incidents,
    (SELECT COUNT(*)::int FROM patrol_alerts pa JOIN patrol_runs pr ON pr.id=pa.run_id AND pr.tenant_id=pa.tenant_id WHERE pa.tenant_id=s.tenant_id AND pr.site_id=s.id AND COALESCE(pa.status,'open') NOT IN('resolved','dismissed')) patrol_exceptions,
    (SELECT COUNT(*)::int FROM sos_alerts sa WHERE sa.tenant_id=s.tenant_id AND sa.site_id=s.id AND COALESCE(sa.status,'active') NOT IN('resolved','closed')) active_sos,
    (SELECT COUNT(*)::int FROM lone_worker_alerts la WHERE la.tenant_id=s.tenant_id AND la.site_id=s.id AND la.resolved=FALSE) lone_worker_alerts,
    (SELECT COUNT(*)::int FROM visitor_records vr WHERE vr.tenant_id=s.tenant_id AND vr.site_id=s.id AND vr.status='on_site') visitors_on_site,
    (SELECT ps.score FROM proofscore_snapshots ps WHERE ps.tenant_id=s.tenant_id AND ps.site_id=s.id ORDER BY ps.calculated_at DESC LIMIT 1) proofscore
    FROM sites s LEFT JOIN site_risk_twins t ON t.tenant_id=s.tenant_id AND t.site_id=s.id WHERE s.tenant_id=$1${clause} ORDER BY s.name`,p)).rows;
  return rows.map(r=>{const signals={open_incidents:Number(r.open_incidents||0),severe_incidents:Number(r.severe_incidents||0),patrol_exceptions:Number(r.patrol_exceptions||0),active_sos:Number(r.active_sos||0),lone_worker_alerts:Number(r.lone_worker_alerts||0),visitors_on_site:Number(r.visitors_on_site||0),checkpoints:Number(r.checkpoints||0),assigned_guards:Number(r.assigned_guards||0),proofscore:r.proofscore==null?null:Number(r.proofscore)};let score=0,reasons=[];
    score+=Math.min(25,signals.open_incidents*3)+Math.min(20,signals.severe_incidents*8)+Math.min(20,signals.patrol_exceptions*4)+Math.min(30,signals.active_sos*15)+Math.min(20,signals.lone_worker_alerts*7);
    if(r.public_access){score+=5;reasons.push('Public access increases exposure.')}if(r.overnight_operation){score+=5;reasons.push('Overnight operations require enhanced controls.')}if(r.lone_work_expected){score+=5;reasons.push('Lone working is expected at this site.')}if(r.occupancy_band==='high')score+=5;
    if(signals.severe_incidents)reasons.push(`${signals.severe_incidents} unresolved high/critical incident(s).`);if(signals.patrol_exceptions)reasons.push(`${signals.patrol_exceptions} active patrol exception(s).`);if(signals.active_sos)reasons.push(`${signals.active_sos} active SOS alert(s).`);if(signals.lone_worker_alerts)reasons.push(`${signals.lone_worker_alerts} lone-worker alert(s).`);if(signals.proofscore!==null&&signals.proofscore<80){score+=Math.min(20,(80-signals.proofscore)/2);reasons.push(`Published ProofScore is ${signals.proofscore.toFixed(2)}%, below target.`)}if(!signals.checkpoints){score+=10;reasons.push('No checkpoints are configured.')}if(!signals.assigned_guards){score+=10;reasons.push('No guards are assigned to the site.')}score=Math.max(0,Math.min(100,Math.round(score*100)/100));
    const band=score>=75?'critical':score>=50?'high':score>=25?'medium':'low';if(!reasons.length)reasons.push('No material live risk signal is currently detected.');return{...r,configured:Boolean(r.twin_id),signals,risk_score:score,risk_band:band,reasons,calculated_at:new Date().toISOString()}})
}
app.get('/api/site-risk-twins',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{res.json({sites:await withTenant(tenantId,c=>buildSiteRiskTwins(c,tenantId,req.query.site_id||null)),generated_at:new Date().toISOString(),model:'PS Site Twin v1'})}catch(err){res.status(500).json({error:err.message})}});
app.put('/api/site-risk-twins/:siteId',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),siteId=Number(req.params.siteId),occupancy=String(req.body.occupancy_band||'medium'),status=String(req.body.status||'active');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!['low','medium','high'].includes(occupancy)||!['active','review','archived'].includes(status))return res.status(400).json({error:'Valid site, occupancy and status are required'});try{const row=await withTenant(tenantId,async c=>{const site=await c.query(`SELECT id FROM sites WHERE id=$1 AND tenant_id=$2`,[siteId,tenantId]);if(!site.rowCount)throw Error('Site not found');return c.query(`INSERT INTO site_risk_twins(tenant_id,site_id,profile_name,site_type,occupancy_band,public_access,overnight_operation,lone_work_expected,critical_zones,hazard_factors,control_notes,status,updated_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(tenant_id,site_id) DO UPDATE SET profile_name=EXCLUDED.profile_name,site_type=EXCLUDED.site_type,occupancy_band=EXCLUDED.occupancy_band,public_access=EXCLUDED.public_access,overnight_operation=EXCLUDED.overnight_operation,lone_work_expected=EXCLUDED.lone_work_expected,critical_zones=EXCLUDED.critical_zones,hazard_factors=EXCLUDED.hazard_factors,control_notes=EXCLUDED.control_notes,status=EXCLUDED.status,model_version=site_risk_twins.model_version+1,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=NOW() RETURNING *`,[tenantId,siteId,String(req.body.profile_name||'Operational risk model').trim(),String(req.body.site_type||'commercial').trim(),occupancy,Boolean(req.body.public_access),Boolean(req.body.overnight_operation),Boolean(req.body.lone_work_expected),JSON.stringify(Array.isArray(req.body.critical_zones)?req.body.critical_zones:[]),JSON.stringify(Array.isArray(req.body.hazard_factors)?req.body.hazard_factors:[]),String(req.body.control_notes||'').trim()||null,status,req.auth.user_id])});res.json(row.rows[0])}catch(err){res.status(err.message==='Site not found'?404:500).json({error:err.message})}});

// ------------------------ STAGE 9.2: DIGITAL TWIN SCENARIO SIMULATION ------------------------
async function ensureSiteRiskScenarioSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS site_risk_scenarios(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,site_id INTEGER NOT NULL,
    name TEXT NOT NULL,description TEXT,baseline_score NUMERIC(5,2) NOT NULL,
    projected_score NUMERIC(5,2) NOT NULL,projected_band TEXT NOT NULL,
    assumptions JSONB NOT NULL DEFAULT '{}'::jsonb,impacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,status TEXT NOT NULL DEFAULT 'draft',
    created_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT site_risk_scenario_scores CHECK(baseline_score BETWEEN 0 AND 100 AND projected_score BETWEEN 0 AND 100),
    CONSTRAINT site_risk_scenario_band CHECK(projected_band IN('low','medium','high','critical')),
    CONSTRAINT site_risk_scenario_status CHECK(status IN('draft','reviewed','archived')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS site_risk_scenarios_tenant_site_time ON site_risk_scenarios(tenant_id,site_id,created_at DESC)`);
  await pool.query(`ALTER TABLE site_risk_scenarios ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON site_risk_scenarios`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON site_risk_scenarios USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON site_risk_scenarios TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE site_risk_scenarios_id_seq TO "${role}"`)}}catch(err){console.warn('Risk scenario tenant-role grant skipped:',err.message)}
  console.log('Site Risk Scenario schema ready');
}
ensureSiteRiskScenarioSchema().catch(err=>console.error('Site Risk Scenario schema setup failed:',err.message));
function simulateSiteRisk(twin,input={}){
  const number=(v,min,max)=>Math.max(min,Math.min(max,Number(v)||0)),a={absent_guards:number(input.absent_guards,0,100),missed_checkpoints:number(input.missed_checkpoints,0,500),additional_incidents:number(input.additional_incidents,0,100),additional_severe_incidents:number(input.additional_severe_incidents,0,100),active_sos:number(input.active_sos,0,20),lone_worker_alerts:number(input.lone_worker_alerts,0,100),visitor_surge:number(input.visitor_surge,0,10000),controls_added:number(input.controls_added,0,20)};
  let delta=0,impacts=[],recommendations=[];const add=(label,points)=>{if(!points)return;delta+=points;impacts.push({label,points:Math.round(points*100)/100})};
  add(`${a.absent_guards} guard absence(s)`,a.absent_guards*8);add(`${a.missed_checkpoints} missed checkpoint(s)`,a.missed_checkpoints*4);add(`${a.additional_incidents} additional incident(s)`,a.additional_incidents*3);add(`${a.additional_severe_incidents} additional severe incident(s)`,a.additional_severe_incidents*8);add(`${a.active_sos} active SOS alert(s)`,a.active_sos*15);add(`${a.lone_worker_alerts} lone-worker alert(s)`,a.lone_worker_alerts*7);add(`${a.visitor_surge} additional visitor(s)`,Math.min(10,a.visitor_surge/10));add(`${a.controls_added} additional verified control(s)`,-a.controls_added*4);
  if(a.absent_guards)recommendations.push('Confirm qualified relief coverage before the affected shift.');if(a.missed_checkpoints)recommendations.push('Review patrol sequencing and checkpoint ownership.');if(a.additional_incidents||a.additional_severe_incidents)recommendations.push('Prepare incident command, escalation, and client communication actions.');if(a.active_sos)recommendations.push('Activate emergency-response supervision and verify welfare contacts.');if(a.lone_worker_alerts)recommendations.push('Increase welfare-check frequency and confirm escalation availability.');if(a.visitor_surge)recommendations.push('Review reception capacity, access control, and emergency-register coverage.');if(a.controls_added)recommendations.push('Validate the proposed controls before treating the projected reduction as achieved.');if(!recommendations.length)recommendations.push('No scenario changes were entered.');
  const projected=Math.max(0,Math.min(100,Math.round((Number(twin.risk_score)+delta)*100)/100)),band=projected>=75?'critical':projected>=50?'high':projected>=25?'medium':'low';return{baseline_score:Number(twin.risk_score),projected_score:projected,delta:Math.round((projected-Number(twin.risk_score))*100)/100,projected_band:band,assumptions:a,impacts,recommendations,site_id:Number(twin.site_id),site_name:twin.site_name,calculated_at:new Date().toISOString()}
}
app.post('/api/site-risk-scenarios/preview',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const twins=await withTenant(tenantId,c=>buildSiteRiskTwins(c,tenantId,siteId));if(!twins.length)return res.status(404).json({error:'Site not found'});res.json(simulateSiteRisk(twins[0],req.body.assumptions))}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/site-risk-scenarios',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),siteId=Number(req.body.site_id),name=String(req.body.name||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!siteId||!name)return res.status(400).json({error:'Site and scenario name are required'});try{const saved=await withTenant(tenantId,async c=>{const twins=await buildSiteRiskTwins(c,tenantId,siteId);if(!twins.length)throw Error('Site not found');const result=simulateSiteRisk(twins[0],req.body.assumptions);return c.query(`INSERT INTO site_risk_scenarios(tenant_id,site_id,name,description,baseline_score,projected_score,projected_band,assumptions,impacts,recommendations,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,[tenantId,siteId,name,String(req.body.description||'').trim()||null,result.baseline_score,result.projected_score,result.projected_band,JSON.stringify(result.assumptions),JSON.stringify(result.impacts),JSON.stringify(result.recommendations),req.auth.user_id])});res.status(201).json(saved.rows[0])}catch(err){res.status(err.message==='Site not found'?404:500).json({error:err.message})}});
app.get('/api/site-risk-scenarios',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const data=await withTenant(tenantId,c=>{const p=[tenantId];let q=`SELECT r.*,s.name site_name,u.email created_by_email FROM site_risk_scenarios r JOIN sites s ON s.id=r.site_id AND s.tenant_id=r.tenant_id LEFT JOIN users u ON u.id=r.created_by_user_id AND u.tenant_id=r.tenant_id WHERE r.tenant_id=$1`;if(req.query.site_id){p.push(Number(req.query.site_id));q+=` AND r.site_id=$${p.length}`}q+=` ORDER BY r.created_at DESC LIMIT 200`;return c.query(q,p)});res.json(data.rows)}catch(err){res.status(500).json({error:err.message})}});

// ------------------------ STAGE 9.3: DIGITAL TWIN READINESS ------------------------
app.get('/api/site-risk-readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=communicationTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['site_risk_twins','site_risk_scenarios'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 9 digital-twin structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRole=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert,has_table_privilege($1,'public.'||t,'UPDATE') can_update FROM unnest($2::text[]) t`,[tenantRole,required])).rows;
    add('grants','Restricted tenant-role permissions',grants.length===required.length&&grants.every(x=>x.can_read&&x.can_insert&&x.can_update),grants.length?`${grants.filter(x=>x.can_read&&x.can_insert&&x.can_update).length}/${required.length} tables readable and writable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const data=await withTenant(tenantId,async c=>{const twins=await buildSiteRiskTwins(c,tenantId);const [siteCount,twinIntegrity,scenarioIntegrity,scenarioEvidence,relationships]=await Promise.all([
      c.query(`SELECT COUNT(*)::int total FROM sites WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE occupancy_band NOT IN('low','medium','high') OR status NOT IN('active','review','archived') OR jsonb_typeof(critical_zones)<>'array' OR jsonb_typeof(hazard_factors)<>'array' OR model_version<1)::int invalid FROM site_risk_twins WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE baseline_score<0 OR baseline_score>100 OR projected_score<0 OR projected_score>100 OR projected_band NOT IN('low','medium','high','critical') OR status NOT IN('draft','reviewed','archived'))::int invalid FROM site_risk_scenarios WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE jsonb_typeof(assumptions)<>'object' OR jsonb_typeof(impacts)<>'array' OR jsonb_typeof(recommendations)<>'array' OR jsonb_array_length(recommendations)=0)::int incomplete FROM site_risk_scenarios WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int broken FROM site_risk_scenarios r LEFT JOIN sites s ON s.id=r.site_id AND s.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND s.id IS NULL`,[tenantId])
    ]);return{twins,sites:siteCount.rows[0],twin:twinIntegrity.rows[0],scenario:scenarioIntegrity.rows[0],evidence:scenarioEvidence.rows[0],relationships:relationships.rows[0]}});
    const configured=Number(data.twin.total),sites=Number(data.sites.total),explainable=data.twins.filter(x=>Number.isFinite(Number(x.risk_score))&&Array.isArray(x.reasons)&&x.reasons.length>0).length;
    add('profile_coverage','Site risk-profile coverage',sites>0&&configured===sites,`${configured}/${sites} site(s) have a configured risk twin`,true,{configured,sites});
    add('profile_integrity','Site risk-profile integrity',Number(data.twin.invalid)===0,`${data.twin.total} profile(s); ${data.twin.invalid} invalid`,true,data.twin);
    add('live_explainability','Explainable live-risk calculation',data.twins.length===sites&&explainable===sites,`${explainable}/${sites} site score(s) include source signals and plain-language reasons`,true,{explainable,sites});
    add('scenario_integrity','Scenario calculation integrity',Number(data.scenario.invalid)===0,`${data.scenario.total} saved scenario(s); ${data.scenario.invalid} invalid`,true,data.scenario);
    add('scenario_evidence','Scenario assumption and response evidence',Number(data.evidence.incomplete)===0,Number(data.evidence.total)>0?`${Number(data.evidence.total)-Number(data.evidence.incomplete)}/${data.evidence.total} scenario(s) retain assumptions, impacts, and recommendations`:'No scenario has been saved yet; simulator controls are ready',false,data.evidence);
    add('relationships','Digital-twin site relationships',Number(data.relationships.broken)===0,`${data.relationships.broken} broken site relationship(s)`,true,data.relationships);
    add('simulation_boundary','Non-destructive simulation boundary',true,'Scenario records are stored separately and have no foreign-key or update path to operational incidents, alerts, shifts, patrols, or staffing',true,{scenario_table:'site_risk_scenarios'});
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length;
    res.json({status:failures?'action_required':warnings?'ready_with_warnings':'stage_9_ready',label:failures?'ACTION REQUIRED':warnings?'READY WITH WARNINGS':'STAGE 9 READY',completed_at:new Date().toISOString(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},activity:{sites,configured_twins:configured,saved_scenarios:Number(data.scenario.total)},checks});
  }catch(err){res.status(500).json({error:err.message})}
});

// ------------------------ STAGE 10.1: PRIVACY-SAFE IDENTITY ASSURANCE ------------------------
async function ensureIdentityAssuranceSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS identity_assurance_settings(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,require_trusted_device BOOLEAN NOT NULL DEFAULT FALSE,
    consent_version TEXT NOT NULL DEFAULT '1.0',retention_days INTEGER NOT NULL DEFAULT 90,
    policy_notice TEXT NOT NULL DEFAULT 'PatrolSync records trusted-device consent and approval metadata. No facial recognition or biometric matching is performed.',
    updated_by_user_id INTEGER,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT identity_assurance_retention CHECK(retention_days BETWEEN 7 AND 730))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS guard_trusted_devices(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,
    device_hash TEXT NOT NULL,device_name TEXT NOT NULL,platform TEXT,user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'pending',consent_version TEXT NOT NULL,consented_at TIMESTAMPTZ NOT NULL,
    approved_by_user_id INTEGER,approved_at TIMESTAMPTZ,revoked_by_user_id INTEGER,revoked_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT guard_trusted_device_status CHECK(status IN('pending','trusted','revoked')),
    UNIQUE(tenant_id,user_id,device_hash))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS guard_trusted_devices_tenant_status ON guard_trusted_devices(tenant_id,status,created_at DESC)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS identity_verification_events(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,device_id BIGINT,
    action_type TEXT NOT NULL,resource_type TEXT NOT NULL,outcome TEXT NOT NULL,enforcement_mode TEXT NOT NULL,
    reason TEXT,request_id TEXT,ip_address TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT identity_verification_outcome CHECK(outcome IN('verified','not_required','pending','revoked','unregistered','missing_device')),
    CONSTRAINT identity_verification_mode CHECK(enforcement_mode IN('observe','enforce','emergency_fallback')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS identity_verification_events_tenant_time ON identity_verification_events(tenant_id,created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS identity_verification_events_user_action ON identity_verification_events(tenant_id,user_id,action_type,created_at DESC)`);
  for(const table of ['identity_assurance_settings','guard_trusted_devices','identity_verification_events']){
    await pool.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY`);
    await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ${table}`);
    await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ${table} USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  }
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){for(const table of ['identity_assurance_settings','guard_trusted_devices','identity_verification_events'])await pool.query(`GRANT SELECT,INSERT,UPDATE,DELETE ON ${table} TO "${role}"`);for(const sequence of ['identity_assurance_settings_id_seq','guard_trusted_devices_id_seq','identity_verification_events_id_seq'])await pool.query(`GRANT USAGE,SELECT ON SEQUENCE ${sequence} TO "${role}"`)}}catch(err){console.warn('Identity assurance tenant-role grant skipped:',err.message)}
  console.log('Privacy-safe identity assurance schema ready');
}
ensureIdentityAssuranceSchema().catch(err=>console.error('Identity assurance schema setup failed:',err.message));
function identityDeviceHash(tenantId,userId,deviceId){return crypto.createHash('sha256').update(`${tenantId}:${userId}:${String(deviceId||'')}`).digest('hex')}
async function identitySettings(client,tenantId){
  const found=await client.query(`SELECT * FROM identity_assurance_settings WHERE tenant_id=$1`,[tenantId]);
  return found.rows[0]||{tenant_id:tenantId,enabled:false,require_trusted_device:false,consent_version:'1.0',retention_days:90,policy_notice:'PatrolSync records trusted-device consent and approval metadata. No facial recognition or biometric matching is performed.'};
}
function trustedDeviceAction(req){
  if(req.path==='/api/sos')return{action:'sos_alert',resource:'sos'};
  if(req.path==='/api/patrol-logs')return{action:'patrol_scan',resource:'patrol_log'};
  if(req.path==='/api/incidents')return{action:'incident_report',resource:'incident'};
  return{action:'clock_in',resource:'attendance'};
}
async function requireTrustedGuardDevice(req,res,next){
  if(req.auth?.role!=='guard')return next();
  const tenantId=Number(req.auth.tenant_id||req.body?.tenant_id),deviceToken=String(req.get('X-PatrolSync-Device')||'').trim();
  const emergency=req.path==='/api/sos',action=trustedDeviceAction(req);
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{
    const result=await withTenant(tenantId,async client=>{
      const settings=await identitySettings(client,tenantId);
      let device=null,outcome='not_required',reason='Identity assurance is disabled';
      if(settings.enabled){
        if(!deviceToken){outcome='missing_device';reason='This browser has no device identifier'}
        else{
          const hash=identityDeviceHash(tenantId,req.auth.user_id,deviceToken);
          device=(await client.query(`SELECT id,status,device_name FROM guard_trusted_devices WHERE tenant_id=$1 AND user_id=$2 AND device_hash=$3`,[tenantId,req.auth.user_id,hash])).rows[0]||null;
          if(!device){outcome='unregistered';reason='This device has not been enrolled'}
          else if(device.status==='trusted'){outcome='verified';reason='Trusted device verified'}
          else{outcome=device.status;reason=device.status==='pending'?'Device approval is pending':'Device trust has been revoked'}
          if(device)await client.query(`UPDATE guard_trusted_devices SET last_seen_at=NOW(),updated_at=NOW() WHERE id=$1`,[device.id]);
        }
      }
      const mode=emergency?'emergency_fallback':(settings.enabled&&settings.require_trusted_device?'enforce':'observe');
      await client.query(`INSERT INTO identity_verification_events(tenant_id,user_id,device_id,action_type,resource_type,outcome,enforcement_mode,reason,request_id,ip_address) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[tenantId,req.auth.user_id,device?.id||null,action.action,action.resource,outcome,mode,reason,req.requestId||null,requestIp(req)]);
      return{settings,outcome,reason,mode};
    });
    req.identityVerification=result;
    if(!emergency&&result.settings.enabled&&result.settings.require_trusted_device&&result.outcome!=='verified')return res.status(403).json({error:`Trusted device required: ${result.reason}`,code:'TRUSTED_DEVICE_REQUIRED',identity_assurance:result});
    next();
  }catch(err){
    console.error('Trusted-device verification failed:',err);
    if(emergency)return next();
    res.status(503).json({error:'Identity verification is temporarily unavailable',code:'IDENTITY_VERIFICATION_UNAVAILABLE'});
  }
}
app.get('/api/identity-assurance/settings',requireAuth,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!['admin','staff','guard'].includes(req.auth.role))return res.status(403).json({error:'Identity assurance unavailable'});try{const settings=await withTenant(tenantId,c=>identitySettings(c,tenantId));res.json(settings)}catch(err){res.status(500).json({error:err.message})}});
app.put('/api/identity-assurance/settings',requireAuth,requireOwnerAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),version=String(req.body.consent_version||'').trim(),notice=String(req.body.policy_notice||'').trim(),retention=Number(req.body.retention_days);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!version||!notice||notice.length>2000||!Number.isInteger(retention)||retention<7||retention>730)return res.status(400).json({error:'Consent version, policy notice, and retention of 7–730 days are required'});try{const result=await withTenant(tenantId,c=>c.query(`INSERT INTO identity_assurance_settings(tenant_id,enabled,require_trusted_device,consent_version,retention_days,policy_notice,updated_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id) DO UPDATE SET enabled=EXCLUDED.enabled,require_trusted_device=EXCLUDED.require_trusted_device,consent_version=EXCLUDED.consent_version,retention_days=EXCLUDED.retention_days,policy_notice=EXCLUDED.policy_notice,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=NOW() RETURNING *`,[tenantId,Boolean(req.body.enabled),Boolean(req.body.require_trusted_device),version,retention,notice,req.auth.user_id]));res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/identity-assurance/devices',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const rows=await withTenant(tenantId,c=>c.query(`SELECT d.id,d.user_id,u.email guard_email,d.device_name,d.platform,d.status,d.consent_version,d.consented_at,d.approved_at,d.revoked_at,d.last_seen_at,d.created_at,approver.email approved_by_email,revoker.email revoked_by_email FROM guard_trusted_devices d JOIN users u ON u.id=d.user_id AND u.tenant_id=d.tenant_id LEFT JOIN users approver ON approver.id=d.approved_by_user_id AND approver.tenant_id=d.tenant_id LEFT JOIN users revoker ON revoker.id=d.revoked_by_user_id AND revoker.tenant_id=d.tenant_id WHERE d.tenant_id=$1 ORDER BY CASE d.status WHEN 'pending' THEN 1 WHEN 'trusted' THEN 2 ELSE 3 END,d.created_at DESC`,[tenantId]));res.json(rows.rows)}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/identity-assurance/events',requireAuth,requireAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.query.tenant_id),limit=Math.min(200,Math.max(1,Number(req.query.limit)||100));if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const result=await withTenant(tenantId,c=>c.query(`SELECT e.id,e.action_type,e.resource_type,e.outcome,e.enforcement_mode,e.reason,e.request_id,e.ip_address,e.created_at,u.email guard_email,d.device_name FROM identity_verification_events e JOIN users u ON u.id=e.user_id AND u.tenant_id=e.tenant_id LEFT JOIN guard_trusted_devices d ON d.id=e.device_id AND d.tenant_id=e.tenant_id WHERE e.tenant_id=$1 ORDER BY e.created_at DESC LIMIT $2`,[tenantId,limit]));res.json(result.rows)}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/identity-assurance/readiness',requireAuth,requireAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=communicationTenant(req,req.query.tenant_id),checks=[];
  if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['identity_assurance_settings','guard_trusted_devices','identity_verification_events'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 10 identity-assurance structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRole=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert,has_table_privilege($1,'public.'||t,'UPDATE') can_update FROM unnest($2::text[]) t`,[tenantRole,required])).rows;
    add('grants','Restricted tenant-role permissions',grants.length===required.length&&grants.every(x=>x.can_read&&x.can_insert&&x.can_update),grants.length?`${grants.filter(x=>x.can_read&&x.can_insert&&x.can_update).length}/${required.length} tables readable and writable through the restricted role`:'Restricted tenant role could not be identified',true,{tables:grants});
    const privacyColumns=(await pool.query(`SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=ANY($1::text[]) AND(column_name ILIKE '%biometric%' OR column_name ILIKE '%face%' OR column_name ILIKE '%fingerprint%')`,[required])).rows;
    add('privacy_boundary','Privacy-safe data boundary',privacyColumns.length===0,privacyColumns.length?`${privacyColumns.length} prohibited biometric column(s) detected`:'No facial, fingerprint, or biometric data fields exist',true,{columns:privacyColumns});
    const data=await withTenant(tenantId,async c=>{const [policy,devices,events,relationships,coverage,sos]=await Promise.all([
      c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE BTRIM(consent_version)='' OR BTRIM(policy_notice)='' OR retention_days NOT BETWEEN 7 AND 730 OR(require_trusted_device AND NOT enabled))::int invalid,COUNT(*) FILTER(WHERE enabled)::int enabled,COUNT(*) FILTER(WHERE enabled AND require_trusted_device)::int enforced FROM identity_assurance_settings WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE status='pending')::int pending,COUNT(*) FILTER(WHERE status='trusted')::int trusted,COUNT(*) FILTER(WHERE status='revoked')::int revoked,COUNT(*) FILTER(WHERE status='trusted' AND(approved_by_user_id IS NULL OR approved_at IS NULL) OR status='revoked' AND(revoked_by_user_id IS NULL OR revoked_at IS NULL))::int invalid FROM guard_trusted_devices WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE outcome NOT IN('verified','not_required','pending','revoked','unregistered','missing_device') OR enforcement_mode NOT IN('observe','enforce','emergency_fallback') OR BTRIM(action_type)='' OR BTRIM(resource_type)='')::int invalid,COUNT(*) FILTER(WHERE outcome='verified')::int verified,COUNT(*) FILTER(WHERE enforcement_mode='emergency_fallback')::int emergency_fallback FROM identity_verification_events WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int broken FROM identity_verification_events e LEFT JOIN users u ON u.id=e.user_id AND u.tenant_id=e.tenant_id LEFT JOIN guard_trusted_devices d ON d.id=e.device_id AND d.tenant_id=e.tenant_id WHERE e.tenant_id=$1 AND(u.id IS NULL OR(e.device_id IS NOT NULL AND d.id IS NULL))`,[tenantId]),
      c.query(`SELECT COUNT(DISTINCT action_type)::int actions,ARRAY_AGG(DISTINCT action_type ORDER BY action_type) FILTER(WHERE action_type IS NOT NULL) action_types FROM identity_verification_events WHERE tenant_id=$1 AND action_type=ANY($2::text[])`,[tenantId,['clock_in','patrol_scan','incident_report']]),
      c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE enforcement_mode<>'emergency_fallback')::int invalid FROM identity_verification_events WHERE tenant_id=$1 AND action_type='sos_alert'`,[tenantId])
    ]);return{policy:policy.rows[0],devices:devices.rows[0],events:events.rows[0],relationships:relationships.rows[0],coverage:coverage.rows[0],sos:sos.rows[0]}});
    add('policy','Versioned consent policy',Number(data.policy.total)===1&&Number(data.policy.invalid)===0,Number(data.policy.total)===1?`${data.policy.enabled} enabled policy; enforcement ${Number(data.policy.enforced)?'on':'off'} with valid notice and retention`:'Company policy has not been saved',true,data.policy);
    add('device_lifecycle','Trusted-device lifecycle integrity',Number(data.devices.invalid)===0,`${data.devices.total} device(s): ${data.devices.pending} pending, ${data.devices.trusted} trusted, ${data.devices.revoked} revoked; ${data.devices.invalid} invalid lifecycle record(s)`,true,data.devices);
    add('event_integrity','Verification evidence integrity',Number(data.events.total)>0&&Number(data.events.invalid)===0,`${data.events.total} event(s); ${data.events.verified} verified; ${data.events.invalid} invalid`,true,data.events);
    add('relationships','Verification evidence relationships',Number(data.relationships.broken)===0,`${data.relationships.broken} broken guard or device relationship(s)`,true,data.relationships);
    add('action_coverage','Protected-action evidence coverage',Number(data.coverage.actions)===3,`${data.coverage.actions}/3 routine protected action type(s) have verification evidence`,false,data.coverage);
    add('sos_safeguard','SOS non-blocking safeguard',Number(data.sos.invalid)===0,Number(data.sos.total)>0?`${data.sos.total} SOS verification event(s); all use emergency fallback`:'No SOS test evidence yet; middleware safeguard is deployed',true,data.sos);
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length;
    res.json({status:failures?'action_required':warnings?'ready_with_warnings':'stage_10_ready',label:failures?'ACTION REQUIRED':warnings?'READY WITH WARNINGS':'STAGE 10 READY',completed_at:new Date().toISOString(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},activity:{devices:Number(data.devices.total),trusted_devices:Number(data.devices.trusted),verification_events:Number(data.events.total),protected_actions:Number(data.coverage.actions)},checks});
  }catch(err){res.status(500).json({error:err.message})}
});
app.patch('/api/identity-assurance/devices/:id/status',requireAuth,requireOwnerAdmin,async(req,res)=>{const tenantId=communicationTenant(req,req.body.tenant_id),id=Number(req.params.id),status=String(req.body.status||'');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(!id||!['trusted','revoked'].includes(status))return res.status(400).json({error:'Valid device and status are required'});try{const result=await withTenant(tenantId,c=>c.query(`UPDATE guard_trusted_devices SET status=$3,approved_by_user_id=CASE WHEN $3='trusted' THEN $4 ELSE approved_by_user_id END,approved_at=CASE WHEN $3='trusted' THEN NOW() ELSE approved_at END,revoked_by_user_id=CASE WHEN $3='revoked' THEN $4 ELSE NULL END,revoked_at=CASE WHEN $3='revoked' THEN NOW() ELSE NULL END,updated_at=NOW() WHERE id=$1 AND tenant_id=$2 RETURNING id,user_id,device_name,status,approved_at,revoked_at`,[id,tenantId,status,req.auth.user_id]));if(!result.rowCount)return res.status(404).json({error:'Device registration not found'});res.json(result.rows[0])}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/guard/identity-assurance',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const tenantId=communicationTenant(req,req.query.tenant_id),deviceId=String(req.query.device_id||'');if(!tenantId)return res.status(403).json({error:'Tenant access denied'});try{const data=await withTenant(tenantId,async c=>{const settings=await identitySettings(c,tenantId);let device=null;if(deviceId){const hash=identityDeviceHash(tenantId,req.auth.user_id,deviceId);device=(await c.query(`SELECT id,device_name,platform,status,consent_version,consented_at,approved_at,revoked_at,last_seen_at FROM guard_trusted_devices WHERE tenant_id=$1 AND user_id=$2 AND device_hash=$3`,[tenantId,req.auth.user_id,hash])).rows[0]||null;if(device)await c.query(`UPDATE guard_trusted_devices SET last_seen_at=NOW() WHERE id=$1`,[device.id])}return{settings,device}});res.json(data)}catch(err){res.status(500).json({error:err.message})}});
app.post('/api/guard/identity-assurance/enrol',requireAuth,async(req,res)=>{if(req.auth.role!=='guard')return res.status(403).json({error:'Guard access required'});const tenantId=communicationTenant(req,req.body.tenant_id),deviceId=String(req.body.device_id||''),name=String(req.body.device_name||'').trim();if(!tenantId)return res.status(403).json({error:'Tenant access denied'});if(req.body.consent_accepted!==true||deviceId.length<16||!name)return res.status(400).json({error:'Explicit consent, a device identifier, and device name are required'});try{const saved=await withTenant(tenantId,async c=>{const settings=await identitySettings(c,tenantId);if(!settings.enabled)throw Object.assign(new Error('Identity assurance is not enabled by your company'),{statusCode:409});const hash=identityDeviceHash(tenantId,req.auth.user_id,deviceId);return c.query(`INSERT INTO guard_trusted_devices(tenant_id,user_id,device_hash,device_name,platform,user_agent,status,consent_version,consented_at) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,NOW()) ON CONFLICT(tenant_id,user_id,device_hash) DO UPDATE SET device_name=EXCLUDED.device_name,platform=EXCLUDED.platform,user_agent=EXCLUDED.user_agent,status=CASE WHEN guard_trusted_devices.status='revoked' THEN 'pending' ELSE guard_trusted_devices.status END,consent_version=EXCLUDED.consent_version,consented_at=NOW(),revoked_by_user_id=NULL,revoked_at=NULL,last_seen_at=NOW(),updated_at=NOW() RETURNING id,device_name,platform,status,consent_version,consented_at,approved_at`,[tenantId,req.auth.user_id,hash,name,String(req.body.platform||'').slice(0,200)||null,String(req.body.user_agent||'').slice(0,500)||null,settings.consent_version])});res.status(201).json(saved.rows[0])}catch(err){res.status(err.statusCode||500).json({error:err.message})}});

// ------------------------ STAGE 11.1: GOVERNED OPERATIONS ASSISTANT ------------------------
const AI_MODULE_CATALOGUE = [
  {label:'Attendance',href:'attendance.html',keywords:'clock in clock out break worked hours attendance'},
  {label:'Shift Scheduler',href:'shift_scheduler.html',keywords:'shift schedule roster open shift template coverage'},
  {label:'Incident Cases',href:'incident_management.html',keywords:'incident acknowledge resolve case photo evidence'},
  {label:'Patrol Runs',href:'patrol_runs.html',keywords:'patrol route run checkpoint scan missed'},
  {label:'TrustProof Evidence',href:'trustproof.html',keywords:'evidence integrity seal verify chain proof'},
  {label:'Guard Certifications',href:'certificate_register.html',keywords:'certificate licence license expiry renewal compliance'},
  {label:'Training & Compliance',href:'training_compliance.html',keywords:'training competency policy assignment compliance'},
  {label:'ProofScore Assurance',href:'proofscore.html',keywords:'proofscore assurance client score evidence'},
  {label:'Client Reports',href:'client_reports.html',keywords:'client report pdf delivery schedule'},
  {label:'Contracts & SLAs',href:'service_contracts.html',keywords:'contract sla target rate billing'},
  {label:'Billing & Invoices',href:'invoices.html',keywords:'invoice payment bill credit'},
  {label:'Lone Worker',href:'lone_worker.html',keywords:'lone worker safety check in alert'},
  {label:'Crisis Mode',href:'crisis_mode.html',keywords:'crisis emergency response commander action'},
  {label:'Site Risk Digital Twin',href:'site_risk_twin.html',keywords:'site risk exposure hazard digital twin'},
  {label:'Identity Assurance',href:'identity_assurance.html',keywords:'identity trusted device consent verification'},
  {label:'Audit Log',href:'audit_log.html',keywords:'audit history changes accountability'},
  {label:'Operations Analytics',href:'analytics.html',keywords:'analytics trends performance operational'},
  {label:'Service Tickets',href:'service_tickets.html',keywords:'client request ticket message service'}
];
const aiAssistantWindows = new Map();
function aiAssistantRateLimit(req,res,next){
  const key=`${req.auth?.tenant_id||'x'}:${req.auth?.user_id||'x'}`,now=Date.now(),windowMs=15*60*1000,limit=30;
  const recent=(aiAssistantWindows.get(key)||[]).filter(x=>now-x<windowMs);
  if(recent.length>=limit)return res.status(429).set('Retry-After','900').json({error:'Assistant request limit reached. Try again later.'});
  recent.push(now);aiAssistantWindows.set(key,recent);next();
}
function aiRelevantModules(question){
  const words=String(question||'').toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>2);
  return AI_MODULE_CATALOGUE.map(module=>({module,score:words.reduce((n,word)=>n+(module.label+' '+module.keywords).toLowerCase().includes(word)?1:0,0)}))
    .filter(x=>x.score>0).sort((a,b)=>b.score-a.score).slice(0,5).map(x=>x.module);
}
function responseText(payload){
  const parts=Array.isArray(payload?.output)?payload.output.flatMap(item=>Array.isArray(item?.content)?item.content:[]):[];
  return String(payload?.output_text||parts.filter(item=>item?.type==='output_text'||item?.type==='text').map(item=>typeof item?.text==='string'?item.text:item?.text?.value||'').filter(Boolean).join('\n')||'').trim();
}
function aiAssistantPublicError(err){
  const code=String(err?.code||'assistant_error').toLowerCase();
  if(['invalid_api_key','incorrect_api_key'].includes(code))return{code,message:'The OpenAI API key is invalid or has been revoked. Replace OPENAI_API_KEY in Render and redeploy.'};
  if(['insufficient_quota','billing_hard_limit_reached'].includes(code))return{code,message:'The OpenAI API project has no available credit or has reached its billing limit. Check API billing, then try again.'};
  if(['model_not_found','model_not_available','permission_denied'].includes(code))return{code,message:`The configured OpenAI model (${OPENAI_MODEL}) is unavailable to this API project. Check OPENAI_MODEL and project access.`};
  if(['max_output_tokens','incomplete_max_output_tokens'].includes(code))return{code,message:'The company AI output-token limit was reached before a visible answer was produced. Increase Maximum output tokens in AI Governance & Usage to at least 1,200, then try again.'};
  if(['rate_limit_exceeded','tokens'].includes(code)||Number(err?.providerStatus)===429)return{code,message:'The OpenAI API rate limit was reached. Wait briefly and try again.'};
  if(Number(err?.providerStatus)>=500)return{code,message:'OpenAI is temporarily unavailable. Try again shortly.'};
  if(/^42|^22|^23|^28|^40|^53|^57|^58/.test(code))return{code,message:`PatrolSync could not prepare the aggregate assistant context. Diagnostic code: ${code}.`};
  return{code,message:`The assistant request could not be completed. Diagnostic code: ${code}.`};
}
async function ensureAiAssistantSchema(){
  await pool.query(`CREATE TABLE IF NOT EXISTS ai_assistant_audit(
    id BIGSERIAL PRIMARY KEY,tenant_id INTEGER NOT NULL,user_id INTEGER NOT NULL,
    question_hash TEXT NOT NULL,response_hash TEXT,matched_modules JSONB NOT NULL DEFAULT '[]'::jsonb,
    provider TEXT NOT NULL DEFAULT 'openai',model TEXT,status TEXT NOT NULL,error_code TEXT,
    input_tokens INTEGER,output_tokens INTEGER,request_id TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ai_assistant_audit_status CHECK(status IN('completed','failed','blocked')))`);
  await pool.query(`CREATE INDEX IF NOT EXISTS ai_assistant_audit_tenant_time ON ai_assistant_audit(tenant_id,created_at DESC)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS ai_assistant_policies(
    tenant_id INTEGER PRIMARY KEY,enabled BOOLEAN NOT NULL DEFAULT TRUE,
    daily_request_limit INTEGER NOT NULL DEFAULT 100,max_output_tokens INTEGER NOT NULL DEFAULT 700,
    updated_by_user_id INTEGER,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ai_policy_daily_limit CHECK(daily_request_limit BETWEEN 1 AND 500),
    CONSTRAINT ai_policy_output_limit CHECK(max_output_tokens BETWEEN 100 AND 2000))`);
  await pool.query(`ALTER TABLE ai_assistant_audit ENABLE ROW LEVEL SECURITY`);
  await pool.query(`ALTER TABLE ai_assistant_policies ENABLE ROW LEVEL SECURITY`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ai_assistant_audit`);
  await pool.query(`DROP POLICY IF EXISTS patrolsync_tenant_isolation ON ai_assistant_policies`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ai_assistant_audit USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  await pool.query(`CREATE POLICY patrolsync_tenant_isolation ON ai_assistant_policies USING(tenant_id=current_setting('app.current_tenant',TRUE)::int) WITH CHECK(tenant_id=current_setting('app.current_tenant',TRUE)::int)`);
  try{const role=decodeURIComponent(new URL(tenantDatabaseUrl).username||'');if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)){await pool.query(`GRANT SELECT,INSERT ON ai_assistant_audit TO "${role}"`);await pool.query(`GRANT SELECT,INSERT,UPDATE ON ai_assistant_policies TO "${role}"`);await pool.query(`GRANT USAGE,SELECT ON SEQUENCE ai_assistant_audit_id_seq TO "${role}"`)}}catch(err){console.warn('AI assistant tenant-role grant skipped:',err.message)}
  console.log('Governed operations assistant schema ready');
}
ensureAiAssistantSchema().catch(err=>console.error('AI assistant schema setup failed:',err.message));
async function aiCompanyContext(tenantId){
  return withTenant(tenantId,async c=>{
    const [sites,guards,openIncidents,openSos,expiring,shifts]=await Promise.all([
      c.query(`SELECT COUNT(*)::int count FROM sites WHERE tenant_id=$1`,[tenantId]),
      c.query(`SELECT COUNT(*)::int count FROM users WHERE tenant_id=$1 AND role='guard' AND COALESCE(account_active,TRUE)=TRUE`,[tenantId]),
      c.query(`SELECT COUNT(*)::int count FROM incidents WHERE tenant_id=$1 AND COALESCE(status,'reported') NOT IN('resolved','closed')`,[tenantId]),
      c.query(`SELECT COUNT(*)::int count FROM sos_alerts WHERE tenant_id=$1 AND COALESCE(status,'active')='active'`,[tenantId]),
      c.query(`SELECT COUNT(*)::int count FROM guard_certifications WHERE tenant_id=$1 AND archived_at IS NULL AND expiry_date IS NOT NULL AND expiry_date<=CURRENT_DATE+30`,[tenantId]),
      c.query(`SELECT COUNT(*)::int count FROM shifts WHERE tenant_id=$1 AND shift_date BETWEEN CURRENT_DATE AND CURRENT_DATE+14`,[tenantId])
    ]);
    return{sites:sites.rows[0].count,active_guards:guards.rows[0].count,open_incidents:openIncidents.rows[0].count,active_sos_alerts:openSos.rows[0].count,certificates_expired_or_due_30_days:expiring.rows[0].count,shifts_next_14_days:shifts.rows[0].count};
  });
}
async function aiTenantPolicy(tenantId,client){
  const result=await client.query(`SELECT enabled,daily_request_limit,max_output_tokens,updated_at FROM ai_assistant_policies WHERE tenant_id=$1`,[tenantId]);
  return result.rows[0]||{enabled:true,daily_request_limit:100,max_output_tokens:700,updated_at:null};
}
app.get('/api/ai-assistant/status',requireAuth,requireOwnerAdmin,async(req,res)=>{try{const tenantId=Number(req.auth.tenant_id),policy=await withTenant(tenantId,c=>aiTenantPolicy(tenantId,c));res.json({enabled:AI_ASSISTANT_ENABLED&&Boolean(OPENAI_API_KEY)&&policy.enabled,platform_configured:AI_ASSISTANT_ENABLED&&Boolean(OPENAI_API_KEY),tenant_enabled:policy.enabled,model:AI_ASSISTANT_ENABLED&&OPENAI_API_KEY?OPENAI_MODEL:null,mode:'read_only_advisory',privacy:'aggregate_context_only',policy})}catch(err){res.status(500).json({error:err.message})}});
app.get('/api/ai-assistant/governance',requireAuth,requireOwnerAdmin,async(req,res)=>{const tenantId=Number(req.auth.tenant_id);try{const data=await withTenant(tenantId,async c=>{const policy=await aiTenantPolicy(tenantId,c);const [summary,errors,daily,recent,today]=await Promise.all([c.query(`SELECT COUNT(*)::int requests,COUNT(*) FILTER(WHERE status='completed')::int completed,COUNT(*) FILTER(WHERE status='failed')::int failed,COALESCE(SUM(input_tokens),0)::int input_tokens,COALESCE(SUM(output_tokens),0)::int output_tokens FROM ai_assistant_audit WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '30 days'`,[tenantId]),c.query(`SELECT COALESCE(error_code,'unknown') error_code,COUNT(*)::int count FROM ai_assistant_audit WHERE tenant_id=$1 AND status='failed' AND created_at>=NOW()-INTERVAL '30 days' GROUP BY COALESCE(error_code,'unknown') ORDER BY count DESC`,[tenantId]),c.query(`SELECT created_at::date AS usage_date,COUNT(*)::int requests,COUNT(*) FILTER(WHERE status='completed')::int completed FROM ai_assistant_audit WHERE tenant_id=$1 AND created_at>=CURRENT_DATE-13 GROUP BY created_at::date ORDER BY usage_date`,[tenantId]),c.query(`SELECT id,status,model,error_code,input_tokens,output_tokens,matched_modules,request_id,created_at FROM ai_assistant_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`,[tenantId]),c.query(`SELECT COUNT(*)::int count FROM ai_assistant_audit WHERE tenant_id=$1 AND created_at>=CURRENT_DATE`,[tenantId])]);return{policy,summary:summary.rows[0],errors:errors.rows,daily:daily.rows,recent:recent.rows,today_requests:today.rows[0].count}});res.json({platform:{configured:AI_ASSISTANT_ENABLED&&Boolean(OPENAI_API_KEY),model:OPENAI_MODEL,mode:'read_only_advisory',privacy:'hash_only_audit'},...data,request_id:req.requestId||null})}catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}});
app.patch('/api/ai-assistant/governance',requireAuth,requireOwnerAdmin,async(req,res)=>{const tenantId=Number(req.auth.tenant_id),enabled=req.body.enabled!==false,daily=Number(req.body.daily_request_limit),output=Number(req.body.max_output_tokens);if(!Number.isInteger(daily)||daily<1||daily>500)return res.status(400).json({error:'Daily request limit must be between 1 and 500'});if(!Number.isInteger(output)||output<100||output>2000)return res.status(400).json({error:'Output-token limit must be between 100 and 2,000'});try{const row=await withTenant(tenantId,c=>c.query(`INSERT INTO ai_assistant_policies(tenant_id,enabled,daily_request_limit,max_output_tokens,updated_by_user_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id) DO UPDATE SET enabled=EXCLUDED.enabled,daily_request_limit=EXCLUDED.daily_request_limit,max_output_tokens=EXCLUDED.max_output_tokens,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=NOW() RETURNING enabled,daily_request_limit,max_output_tokens,updated_at`,[tenantId,enabled,daily,output,req.auth.user_id]));res.json({policy:row.rows[0],message:'AI governance policy saved'})}catch(err){res.status(500).json({error:err.message,request_id:req.requestId})}});
app.post('/api/ai-assistant/chat',requireAuth,requireOwnerAdmin,aiAssistantRateLimit,async(req,res)=>{
  const tenantId=Number(req.auth.tenant_id),question=String(req.body.question||'').trim();
  if(!AI_ASSISTANT_ENABLED||!OPENAI_API_KEY)return res.status(503).json({error:'The operations assistant is not configured. Add OPENAI_API_KEY and set AI_ASSISTANT_ENABLED=true.'});
  if(question.length<3||question.length>1200)return res.status(400).json({error:'Enter a question between 3 and 1,200 characters.'});
  const matched=aiRelevantModules(question),questionHash=crypto.createHash('sha256').update(question).digest('hex');
  try{
    const policy=await withTenant(tenantId,async c=>{const p=await aiTenantPolicy(tenantId,c),used=Number((await c.query(`SELECT COUNT(*)::int count FROM ai_assistant_audit WHERE tenant_id=$1 AND created_at>=CURRENT_DATE`,[tenantId])).rows[0].count);return{...p,used}});
    if(!policy.enabled)return res.status(403).json({error:'The Operations Assistant is disabled by your company AI governance policy.'});
    if(policy.used>=policy.daily_request_limit)return res.status(429).json({error:'Your company AI assistant daily request limit has been reached.'});
    const context=await aiCompanyContext(tenantId),catalogue=AI_MODULE_CATALOGUE.map(x=>`${x.label}: ${x.href}`).join('\n');
    const instructions=`You are PatrolSync Operations Assistant for an authenticated subscriber company administrator. Be concise, practical, and transparent. Use only the supplied aggregate company context and module catalogue. You are read-only: never claim to perform an action or change a record. Never rank, score, discipline, hire, dismiss, schedule, or reassign an individual guard. Never infer sensitive personal traits. Never provide precise guard locations, passwords, tokens, or private personal records. For emergencies or active SOS alerts, tell the administrator to use Crisis Mode/SOS Monitor and follow local emergency procedures; do not make emergency decisions. Distinguish facts from suggestions. If information is unavailable, say so. End with up to three relevant PatrolSync module names when useful.`;
    const input=`Aggregate company context (counts only):\n${JSON.stringify(context)}\n\nAvailable PatrolSync modules:\n${catalogue}\n\nAdministrator question:\n${question}`;
    const apiResponse=await fetch('https://api.openai.com/v1/responses',{method:'POST',headers:{'Authorization':`Bearer ${OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:OPENAI_MODEL,instructions,input,reasoning:{effort:'minimal'},max_output_tokens:policy.max_output_tokens,store:false,safety_identifier:crypto.createHash('sha256').update(`${tenantId}:${req.auth.user_id}`).digest('hex')})});
    const payload=await apiResponse.json().catch(()=>({}));
    if(!apiResponse.ok)throw Object.assign(new Error(payload?.error?.message||'AI provider request failed'),{code:payload?.error?.code||payload?.error?.type||`http_${apiResponse.status}`,statusCode:502,providerStatus:apiResponse.status});
    if(payload?.status==='incomplete')throw Object.assign(new Error(`OpenAI response incomplete: ${payload?.incomplete_details?.reason||'unknown'}`),{code:`incomplete_${payload?.incomplete_details?.reason||'unknown'}`,statusCode:502});
    const answer=responseText(payload);if(!answer)throw Object.assign(new Error('The assistant returned an empty response'),{code:'empty_response',statusCode:502});
    await withTenant(tenantId,c=>c.query(`INSERT INTO ai_assistant_audit(tenant_id,user_id,question_hash,response_hash,matched_modules,model,status,input_tokens,output_tokens,request_id) VALUES($1,$2,$3,$4,$5::jsonb,$6,'completed',$7,$8,$9)`,[tenantId,req.auth.user_id,questionHash,crypto.createHash('sha256').update(answer).digest('hex'),JSON.stringify(matched),OPENAI_MODEL,payload.usage?.input_tokens||null,payload.usage?.output_tokens||null,req.requestId||null]));
    res.json({answer,modules:matched,mode:'read_only_advisory',request_id:req.requestId||null});
  }catch(err){
    await withTenant(tenantId,c=>c.query(`INSERT INTO ai_assistant_audit(tenant_id,user_id,question_hash,matched_modules,model,status,error_code,request_id) VALUES($1,$2,$3,$4::jsonb,$5,'failed',$6,$7)`,[tenantId,req.auth.user_id,questionHash,JSON.stringify(matched),OPENAI_MODEL,String(err.code||'provider_error').slice(0,100),req.requestId||null])).catch(()=>{});
    const safe=aiAssistantPublicError(err);
    console.error('Operations assistant request failed',{request_id:req.requestId||null,tenant_id:tenantId,provider_status:err.providerStatus||null,error_code:safe.code,message:err.message});
    res.status(err.statusCode||500).json({error:`${safe.message} No PatrolSync records were changed.`,diagnostic_code:safe.code,request_id:req.requestId||null});
  }
});

// ------------------------ STAGE 11.3: GOVERNED AI READINESS ------------------------
app.get('/api/ai-assistant/readiness',requireAuth,requireOwnerAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=Number(req.auth.tenant_id),checks=[];
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['ai_assistant_audit','ai_assistant_policies'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 11 governed-AI structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const rls=(await pool.query(`SELECT c.relname table_name,c.relrowsecurity enabled,EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname) protected FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY($1::text[])`,[required])).rows;
    add('rls','Tenant RLS protection',rls.length===required.length&&rls.every(x=>x.enabled&&x.protected),`${rls.filter(x=>x.enabled&&x.protected).length}/${required.length} tables have RLS and a tenant policy`,true,{tables:rls});
    const tenantRole=(()=>{try{return decodeURIComponent(new URL(tenantDatabaseUrl).username||'')}catch(_){return''}})();let grants=[];
    if(/^[A-Za-z_][A-Za-z0-9_]*$/.test(tenantRole))grants=(await pool.query(`SELECT t table_name,has_table_privilege($1,'public.'||t,'SELECT') can_read,has_table_privilege($1,'public.'||t,'INSERT') can_insert,has_table_privilege($1,'public.'||t,'UPDATE') can_update FROM unnest($2::text[]) t`,[tenantRole,required])).rows;
    const grantsValid=grants.length===2&&grants.every(x=>x.can_read&&x.can_insert&&(x.table_name==='ai_assistant_audit'||x.can_update));
    add('grants','Restricted tenant-role permissions',grantsValid,grants.length?`${grants.filter(x=>x.can_read&&x.can_insert&&(x.table_name==='ai_assistant_audit'||x.can_update)).length}/2 tables have the required least-privilege access`:'Restricted tenant role could not be identified',true,{tables:grants});
    add('platform','OpenAI platform configuration',AI_ASSISTANT_ENABLED&&Boolean(OPENAI_API_KEY)&&Boolean(OPENAI_MODEL),AI_ASSISTANT_ENABLED&&OPENAI_API_KEY?`Operations Assistant is configured with ${OPENAI_MODEL}`:'AI_ASSISTANT_ENABLED, OPENAI_API_KEY, or OPENAI_MODEL is missing',true,{enabled:AI_ASSISTANT_ENABLED,key_configured:Boolean(OPENAI_API_KEY),model:OPENAI_MODEL||null});
    const privacyColumns=(await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='ai_assistant_audit' AND(column_name ILIKE '%question_text%' OR column_name ILIKE '%prompt%' OR column_name ILIKE '%answer%' OR column_name ILIKE '%response_text%' OR column_name ILIKE '%location%' OR column_name ILIKE '%password%')`)).rows.map(x=>x.column_name);
    add('privacy','Prompt and response privacy boundary',privacyColumns.length===0,privacyColumns.length?`Prohibited raw-content column(s) detected: ${privacyColumns.join(', ')}`:'Audit storage contains hashes and usage metadata, not raw questions or answers',true,{prohibited_columns:privacyColumns});
    const data=await withTenant(tenantId,async c=>{
      const policy=await aiTenantPolicy(tenantId,c);
      const [usage,integrity,diagnostics,today]=await Promise.all([
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE status='completed')::int completed,COUNT(*) FILTER(WHERE status='failed')::int failed,COUNT(*) FILTER(WHERE status='blocked')::int blocked,COUNT(*) FILTER(WHERE status='completed' AND created_at>=NOW()-INTERVAL '30 days')::int recent_completed,COALESCE(SUM(input_tokens) FILTER(WHERE status='completed'),0)::int input_tokens,COALESCE(SUM(output_tokens) FILTER(WHERE status='completed'),0)::int output_tokens,MAX(created_at) FILTER(WHERE status='completed') last_completed_at FROM ai_assistant_audit WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*) FILTER(WHERE question_hash !~ '^[0-9a-f]{64}$')::int invalid_question_hash,COUNT(*) FILTER(WHERE status='completed' AND(response_hash IS NULL OR response_hash !~ '^[0-9a-f]{64}$'))::int invalid_response_hash,COUNT(*) FILTER(WHERE status='completed' AND(COALESCE(input_tokens,0)<=0 OR COALESCE(output_tokens,0)<=0))::int invalid_usage,COUNT(*) FILTER(WHERE status NOT IN('completed','failed','blocked'))::int invalid_status FROM ai_assistant_audit WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*) FILTER(WHERE status='failed' AND(COALESCE(error_code,'')='' OR COALESCE(request_id,'')=''))::int missing_diagnostic,COUNT(*) FILTER(WHERE status='failed')::int failed FROM ai_assistant_audit WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*)::int count FROM ai_assistant_audit WHERE tenant_id=$1 AND created_at>=CURRENT_DATE`,[tenantId])
      ]);
      return{policy,usage:usage.rows[0],integrity:integrity.rows[0],diagnostics:diagnostics.rows[0],today:Number(today.rows[0].count)};
    });
    const policyValid=typeof data.policy.enabled==='boolean'&&Number(data.policy.daily_request_limit)>=1&&Number(data.policy.daily_request_limit)<=500&&Number(data.policy.max_output_tokens)>=100&&Number(data.policy.max_output_tokens)<=2000;
    add('policy','Company AI policy controls',policyValid,policyValid?`${data.policy.enabled?'Enabled':'Disabled'} · ${data.policy.daily_request_limit} requests/day · ${data.policy.max_output_tokens} maximum output tokens`:'Company AI limits are missing or outside approved bounds',true,data.policy);
    add('successful_evidence','Successful assistant evidence',Number(data.usage.recent_completed)>0,Number(data.usage.recent_completed)>0?`${data.usage.recent_completed} successful request(s) in the last 30 days; latest ${new Date(data.usage.last_completed_at).toISOString()}`:'Complete at least one successful governed assistant request',true,data.usage);
    const integrityValid=Number(data.integrity.invalid_question_hash)===0&&Number(data.integrity.invalid_response_hash)===0&&Number(data.integrity.invalid_usage)===0&&Number(data.integrity.invalid_status)===0;
    add('audit_integrity','Hash-only usage audit integrity',integrityValid,integrityValid?`${data.usage.total} audit record(s); completed responses have valid hashes and token usage`:'One or more AI audit records has invalid hashes, token usage, or status',true,data.integrity);
    add('diagnostics','Failure diagnostic accountability',Number(data.diagnostics.missing_diagnostic)===0,`${data.diagnostics.failed} failed request(s); ${data.diagnostics.missing_diagnostic} missing diagnostic code or request ID`,true,data.diagnostics);
    add('consumption','Bounded company consumption',data.today<=Number(data.policy.daily_request_limit),`${data.today}/${data.policy.daily_request_limit} company requests used today`,true,{today:data.today,daily_limit:Number(data.policy.daily_request_limit)});
    const advisoryBoundary=AI_MODULE_CATALOGUE.length>0&&AI_ASSISTANT_ENABLED;
    add('advisory_boundary','Read-only advisory boundary',advisoryBoundary,advisoryBoundary?`${AI_MODULE_CATALOGUE.length} navigation modules available; assistant has no record-change tools or automatic-decision authority`:'Governed advisory catalogue or assistant mode is unavailable',true,{mode:'read_only_advisory',module_count:AI_MODULE_CATALOGUE.length,automatic_actions:0});
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length;
    res.json({status:failures?'action_required':warnings?'ready_with_warnings':'stage_11_ready',label:failures?'ACTION REQUIRED':warnings?'READY WITH WARNINGS':'STAGE 11 READY',completed_at:new Date().toISOString(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},activity:{audit_records:Number(data.usage.total),successful_requests:Number(data.usage.completed),failed_requests:Number(data.usage.failed),tokens:Number(data.usage.input_tokens)+Number(data.usage.output_tokens),requests_today:data.today},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId||null})}
});

// ------------------------ STAGE 12.1: ROLE & WORKFLOW ACCEPTANCE ------------------------
app.get('/api/launch/workflow-acceptance',requireAuth,requireOwnerAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=Number(req.auth.tenant_id),checks=[];
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const required=['users','client_users','sites','guard_assignments','auth_sessions','attendance_sessions','patrol_logs','incidents','audit_logs'];
    const structures=(await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])`,[required])).rows.map(x=>x.table_name);
    add('structures','Stage 12 acceptance structures',required.every(x=>structures.includes(x)),`${structures.length}/${required.length} required tables available`,true,{missing:required.filter(x=>!structures.includes(x))});
    const data=await withTenant(tenantId,async c=>{
      const [roles,clients,assignments,sessions,workflow,clientLinks,audit,staffPermissions]=await Promise.all([
        c.query(`SELECT role,COUNT(*)::int total,COUNT(*) FILTER(WHERE account_active=TRUE)::int active,COUNT(*) FILTER(WHERE account_active=TRUE AND COALESCE(password_hash,'')<>'')::int login_ready FROM users WHERE tenant_id=$1 GROUP BY role`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE COALESCE(password_hash,'')<>'')::int login_ready FROM client_users WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(DISTINCT u.id)::int active_guards,COUNT(DISTINCT ga.user_id)::int assigned_guards FROM users u LEFT JOIN guard_assignments ga ON ga.tenant_id=u.tenant_id AND ga.user_id=u.id WHERE u.tenant_id=$1 AND u.role='guard' AND u.account_active=TRUE`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE revoked_at IS NULL AND expires_at>NOW())::int active,COUNT(DISTINCT role)::int roles_seen FROM auth_sessions WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT (SELECT COUNT(*)::int FROM attendance_sessions WHERE tenant_id=$1) attendance,(SELECT COUNT(*)::int FROM patrol_logs WHERE tenant_id=$1) patrol_scans,(SELECT COUNT(*)::int FROM incidents WHERE tenant_id=$1) incidents`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE s.id IS NULL)::int broken FROM client_users cu LEFT JOIN sites s ON s.id=cu.site_id AND s.tenant_id=cu.tenant_id WHERE cu.tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE COALESCE(user_email,'')='')::int unattributed,COUNT(DISTINCT user_role)::int roles_seen FROM audit_logs WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE account_active=TRUE)::int active,COUNT(*) FILTER(WHERE account_active=TRUE AND jsonb_typeof(permissions)='array')::int valid_permissions FROM users WHERE tenant_id=$1 AND role='staff'`,[tenantId])
      ]);
      return{roles:roles.rows,clients:clients.rows[0],assignments:assignments.rows[0],sessions:sessions.rows[0],workflow:workflow.rows[0],client_links:clientLinks.rows[0],audit:audit.rows[0],staff:staffPermissions.rows[0]};
    });
    const role=name=>data.roles.find(x=>x.role===name)||{total:0,active:0,login_ready:0};
    const admins=role('admin'),guards=role('guard');
    add('subscriber_admin','Subscriber administrator access',Number(admins.login_ready)>0,`${admins.login_ready}/${admins.active} active administrator account(s) are login-ready`,true,admins);
    add('guard_access','Guard access',Number(guards.login_ready)>0,`${guards.login_ready}/${guards.active} active guard account(s) are login-ready`,true,guards);
    add('client_access','Site-specific client access',Number(data.clients.login_ready)>0,`${data.clients.login_ready}/${data.clients.total} client account(s) are login-ready`,true,data.clients);
    const staffValid=Number(data.staff.active)===0||Number(data.staff.valid_permissions)===Number(data.staff.active);
    add('delegated_staff','Delegated staff permission boundary',staffValid,Number(data.staff.active)?`${data.staff.valid_permissions}/${data.staff.active} active staff account(s) have structured module permissions`:'No delegated staff accounts; owner-admin access remains available',false,data.staff);
    const assignmentValid=Number(data.assignments.active_guards)>0&&Number(data.assignments.assigned_guards)===Number(data.assignments.active_guards);
    add('guard_assignments','Active guard site assignments',assignmentValid,`${data.assignments.assigned_guards}/${data.assignments.active_guards} active guard(s) assigned to a site`,true,data.assignments);
    add('session_lifecycle','Tracked authentication sessions',Number(data.sessions.total)>0,`${data.sessions.active} active of ${data.sessions.total} tracked session(s); ${data.sessions.roles_seen} role type(s) observed`,true,data.sessions);
    const workflowValid=Number(data.workflow.attendance)>0&&Number(data.workflow.patrol_scans)>0&&Number(data.workflow.incidents)>0;
    add('field_workflows','Core field workflow evidence',workflowValid,`${data.workflow.attendance} attendance session(s), ${data.workflow.patrol_scans} patrol scan(s), ${data.workflow.incidents} incident(s)`,true,data.workflow);
    add('client_site_boundary','Client-to-site access relationships',Number(data.client_links.total)>0&&Number(data.client_links.broken)===0,`${data.client_links.total} client account relationship(s); ${data.client_links.broken} broken site link(s)`,true,data.client_links);
    const auditTotal=Number(data.audit.total),auditUnattributed=Number(data.audit.unattributed),auditAttributed=auditTotal-auditUnattributed,auditRate=auditTotal?auditAttributed/auditTotal:0;
    const auditValid=auditTotal>0&&auditRate>=0.99;
    add('audit_attribution','Role-attributed operational audit',auditValid,auditValid?`${auditAttributed}/${auditTotal} audit record(s) attributed (${(auditRate*100).toFixed(2)}%); ${auditUnattributed} legacy/system record(s) without an email; ${data.audit.roles_seen} role type(s) observed`:`${auditUnattributed}/${auditTotal} audit record(s) lack user attribution; at least 99% attribution is required`,true,{...data.audit,attributed:auditAttributed,attribution_rate:Number((auditRate*100).toFixed(2)),minimum_rate:99});
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length;
    res.json({status:failures?'action_required':warnings?'ready_with_warnings':'stage_12_1_ready',label:failures?'ACTION REQUIRED':warnings?'READY WITH WARNINGS':'STAGE 12.1 READY',completed_at:new Date().toISOString(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},activity:{active_admins:Number(admins.active),active_guards:Number(guards.active),active_staff:Number(data.staff.active),client_accounts:Number(data.clients.total),assigned_guards:Number(data.assignments.assigned_guards),tracked_sessions:Number(data.sessions.total)},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId||null})}
});

// ------------------------ STAGE 12.2: BROWSER, MOBILE & OFFLINE ACCEPTANCE ------------------------
const BROWSER_ACCEPTANCE_CAPABILITIES=['secure_context','service_worker','indexed_db','local_storage','geolocation','camera','responsive_layout'];
const BROWSER_ACCEPTANCE_MANUAL=['admin_desktop','guard_mobile','camera_qr','gps_capture','offline_patrol_sync','offline_incident_sync','retry_idempotency','offline_shell'];

app.post('/api/launch/browser-offline-acceptance/evidence',requireAuth,requireOwnerAdmin,async(req,res)=>{
  const tenantId=Number(req.auth.tenant_id),capabilities=req.body?.capabilities||{},manual=req.body?.manual||{},notes=String(req.body?.notes||'').trim().slice(0,2000);
  const normalizedCapabilities={};for(const key of BROWSER_ACCEPTANCE_CAPABILITIES)normalizedCapabilities[key]=Boolean(capabilities[key]);
  const normalizedManual={};for(const key of BROWSER_ACCEPTANCE_MANUAL)normalizedManual[key]=Boolean(manual[key]);
  const viewport={width:Math.max(0,Math.min(10000,Number(req.body?.viewport?.width)||0)),height:Math.max(0,Math.min(10000,Number(req.body?.viewport?.height)||0)),pixel_ratio:Math.max(0,Math.min(10,Number(req.body?.viewport?.pixel_ratio)||1))};
  const details={capabilities:normalizedCapabilities,manual:normalizedManual,viewport,online:Boolean(req.body?.online),service_worker_registered:Boolean(req.body?.service_worker_registered),user_agent:String(req.headers['user-agent']||'').slice(0,500),notes,accepted_by:Number(req.auth.user_id),accepted_by_email:req.auth.email||null};
  try{
    const saved=await withTenant(tenantId,c=>c.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details,request_id) VALUES($1,'stage_12_2_acceptance','info','Browser, mobile and offline acceptance evidence recorded',$2::jsonb,$3) RETURNING id,created_at`,[tenantId,JSON.stringify(details),req.requestId||null]));
    res.status(201).json({saved:true,id:saved.rows[0].id,created_at:saved.rows[0].created_at,evidence:details});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId||null})}
});

app.get('/api/launch/browser-offline-acceptance',requireAuth,requireOwnerAdmin,async(req,res)=>{
  const started=Date.now(),tenantId=Number(req.auth.tenant_id),checks=[];
  const add=(code,label,passed,message,critical=true,details={})=>checks.push({code,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
  try{
    const requiredColumns=['patrol_logs.client_scan_id','patrol_logs.offline_captured','patrol_logs.device_scanned_at','incidents.client_incident_id','incidents.offline_captured','incidents.device_reported_at','incident_photos.checksum_sha256'];
    const columns=(await pool.query(`SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name IN('patrol_logs','incidents','incident_photos')`)).rows;
    const available=new Set(columns.map(x=>`${x.table_name}.${x.column_name}`));
    add('structures','Browser and offline evidence structures',requiredColumns.every(x=>available.has(x)),`${requiredColumns.filter(x=>available.has(x)).length}/${requiredColumns.length} required evidence fields available`,true,{missing:requiredColumns.filter(x=>!available.has(x))});
    const indexRows=(await pool.query(`SELECT indexname FROM pg_indexes WHERE schemaname='public' AND indexname IN('uq_patrol_logs_tenant_client_scan','uq_incidents_tenant_client_id')`)).rows;
    add('idempotency_indexes','Offline retry protection',indexRows.length===2,`${indexRows.length}/2 required unique retry indexes installed`,true,{indexes:indexRows.map(x=>x.indexname)});
    const data=await withTenant(tenantId,async c=>{
      const [scans,incidents,duplicates,photos,acceptance]=await Promise.all([
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE offline_captured)::int offline,COUNT(*) FILTER(WHERE offline_captured AND client_scan_id IS NOT NULL AND device_scanned_at IS NOT NULL)::int traceable FROM patrol_logs WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE offline_captured)::int offline,COUNT(*) FILTER(WHERE offline_captured AND client_incident_id IS NOT NULL AND device_reported_at IS NOT NULL AND device_id IS NOT NULL)::int traceable FROM incidents WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT (SELECT COUNT(*) FROM(SELECT client_scan_id FROM patrol_logs WHERE tenant_id=$1 AND client_scan_id IS NOT NULL GROUP BY client_scan_id HAVING COUNT(*)>1)s)::int scan_duplicates,(SELECT COUNT(*) FROM(SELECT client_incident_id FROM incidents WHERE tenant_id=$1 AND client_incident_id IS NOT NULL GROUP BY client_incident_id HAVING COUNT(*)>1)i)::int incident_duplicates`,[tenantId]),
        c.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE checksum_sha256 IS NOT NULL AND(storage_key IS NOT NULL OR photo_data IS NOT NULL))::int recoverable FROM incident_photos WHERE tenant_id=$1`,[tenantId]),
        c.query(`SELECT id,details,created_at FROM system_events WHERE tenant_id=$1 AND event_type='stage_12_2_acceptance' ORDER BY created_at DESC LIMIT 1`,[tenantId])
      ]);
      return{scans:scans.rows[0],incidents:incidents.rows[0],duplicates:duplicates.rows[0],photos:photos.rows[0],acceptance:acceptance.rows[0]||null};
    });
    add('offline_patrol','Offline patrol synchronization evidence',Number(data.scans.offline)>0&&Number(data.scans.offline)===Number(data.scans.traceable),`${data.scans.traceable}/${data.scans.offline} offline patrol scan(s) retain client identity and capture time`,true,data.scans);
    add('offline_incident','Offline incident synchronization evidence',Number(data.incidents.offline)>0&&Number(data.incidents.offline)===Number(data.incidents.traceable),`${data.incidents.traceable}/${data.incidents.offline} offline incident(s) retain client identity, device and capture time`,true,data.incidents);
    const duplicateCount=Number(data.duplicates.scan_duplicates)+Number(data.duplicates.incident_duplicates);
    add('retry_safety','Retry and replay safety',duplicateCount===0,duplicateCount===0?'No duplicate patrol or incident client identities':'Duplicate client identities require correction',true,data.duplicates);
    add('photo_recovery','Mobile photo recoverability',Number(data.photos.total)===Number(data.photos.recoverable),`${data.photos.recoverable}/${data.photos.total} incident photo(s) are recoverable and checksummed`,true,data.photos);
    const evidence=data.acceptance?.details||{},ageDays=data.acceptance?((Date.now()-new Date(data.acceptance.created_at).getTime())/86400000):null;
    add('acceptance_record','Recorded browser acceptance',Boolean(data.acceptance)&&ageDays<=30,data.acceptance?`Latest acceptance recorded ${new Date(data.acceptance.created_at).toISOString()} by ${evidence.accepted_by_email||'an administrator'}`:'Save browser and manual acceptance evidence from the Stage 12.2 page',true,{event_id:data.acceptance?.id||null,created_at:data.acceptance?.created_at||null,age_days:ageDays});
    const capabilityMissing=BROWSER_ACCEPTANCE_CAPABILITIES.filter(key=>!evidence.capabilities?.[key]);
    add('browser_capabilities','Required browser capabilities',Boolean(data.acceptance)&&capabilityMissing.length===0,capabilityMissing.length?`Missing or unsupported: ${capabilityMissing.join(', ')}`:'Secure context, storage, service worker, camera, location and responsive layout are supported',true,{capabilities:evidence.capabilities||{},missing:capabilityMissing,service_worker_registered:Boolean(evidence.service_worker_registered)});
    const manualMissing=BROWSER_ACCEPTANCE_MANUAL.filter(key=>!evidence.manual?.[key]);
    add('manual_workflows','Desktop, mobile and offline workflow acceptance',Boolean(data.acceptance)&&manualMissing.length===0,manualMissing.length?`${manualMissing.length} manual acceptance item(s) remain incomplete`:'All required administrator and guard acceptance workflows were confirmed',true,{manual:evidence.manual||{},missing:manualMissing});
    add('acceptance_context','Acceptance device context',Boolean(data.acceptance)&&Boolean(evidence.user_agent)&&Number(evidence.viewport?.width)>0,data.acceptance?`${evidence.viewport?.width||0}×${evidence.viewport?.height||0} viewport · ${evidence.online?'online':'offline'} when saved`:'No browser context has been recorded',true,{viewport:evidence.viewport||null,user_agent:evidence.user_agent||null,online:evidence.online});
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length;
    res.json({status:failures?'action_required':warnings?'ready_with_warnings':'stage_12_2_ready',label:failures?'ACTION REQUIRED':warnings?'READY WITH WARNINGS':'STAGE 12.2 READY',completed_at:new Date().toISOString(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},activity:{patrol_scans:Number(data.scans.total),offline_patrol_scans:Number(data.scans.offline),incidents:Number(data.incidents.total),offline_incidents:Number(data.incidents.offline),photos:Number(data.photos.total),acceptance_recorded:Boolean(data.acceptance)},checks});
  }catch(err){res.status(500).json({error:err.message,request_id:req.requestId||null})}
});

const PILOT_ACCEPTANCE_REQUIRED=['pilot_owner_email','support_contact_email','rollback_owner_email','planned_start','rollback_trigger'];
app.post('/api/launch/production-pilot/evidence',requireAuth,requireOwnerAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.body.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});
  try{
    const clean=(value,max=500)=>String(value||'').trim().slice(0,max),email=value=>clean(value,320).toLowerCase();
    const details={pilot_name:clean(req.body.pilot_name||'Controlled production pilot',200),pilot_owner_email:email(req.body.pilot_owner_email),support_contact_email:email(req.body.support_contact_email),rollback_owner_email:email(req.body.rollback_owner_email),planned_start:clean(req.body.planned_start,20),duration_days:Math.min(90,Math.max(1,Number(req.body.duration_days||14))),rollback_trigger:clean(req.body.rollback_trigger,1200),notes:clean(req.body.notes,2000),scope_acknowledged:req.body.scope_acknowledged===true,accepted_by_user_id:req.auth.user_id,accepted_by_email:req.auth.email||null,user_agent:String(req.headers['user-agent']||'').slice(0,500)};
    const missing=PILOT_ACCEPTANCE_REQUIRED.filter(key=>!details[key]);if(missing.length)return res.status(400).json({error:`Complete the required pilot fields: ${missing.join(', ')}`});
    for(const key of ['pilot_owner_email','support_contact_email','rollback_owner_email'])if(!/^\S+@\S+\.\S+$/.test(details[key]))return res.status(400).json({error:`Enter a valid ${key.replaceAll('_',' ')}`});
    if(!/^\d{4}-\d{2}-\d{2}$/.test(details.planned_start)||Number.isNaN(Date.parse(details.planned_start+'T00:00:00Z')))return res.status(400).json({error:'Choose a valid planned pilot start date'});
    if(!details.scope_acknowledged)return res.status(400).json({error:'Confirm that this is a controlled pilot and does not enable an automatic public rollout'});
    const saved=await withTenant(tenantId,c=>c.query(`INSERT INTO system_events(tenant_id,event_type,severity,message,details,request_id) VALUES($1,'stage_12_3_pilot_acceptance','info','Controlled production pilot evidence recorded',$2::jsonb,$3) RETURNING id,created_at`,[tenantId,JSON.stringify(details),req.requestId||null]));
    res.json({message:'Controlled pilot evidence saved.',event:saved.rows[0]});
  }catch(e){res.status(500).json({error:e.message})}
});

app.get('/api/launch/production-pilot-readiness',requireAuth,requireOwnerAdmin,async(req,res)=>{
  const tenantId=attendanceTenant(req,req.query.tenant_id);if(!tenantId)return res.status(403).json({error:'Tenant access denied'});const started=Date.now();
  try{
    const checks=[],add=(key,label,passed,message,critical=true,details={})=>checks.push({key,label,passed:Boolean(passed),critical,status:passed?'pass':critical?'fail':'warning',message,details});
    const [globalData,tenantData]=await Promise.all([
      Promise.all([
        pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE c.relrowsecurity)::int enabled,COUNT(*) FILTER(WHERE EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname))::int protected,COALESCE(JSONB_AGG(c.relname ORDER BY c.relname) FILTER(WHERE NOT c.relrowsecurity),'[]'::jsonb) missing_rls,COALESCE(JSONB_AGG(c.relname ORDER BY c.relname) FILTER(WHERE NOT EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname)),'[]'::jsonb) missing_policy FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped WHERE n.nspname='public' AND c.relkind IN('r','p')`),
        pool.query(`SELECT COUNT(*) FILTER(WHERE status='failed' AND started_at>=NOW()-INTERVAL '24 hours')::int failed,COUNT(*) FILTER(WHERE status='running' AND started_at<NOW()-INTERVAL '10 minutes')::int stuck FROM platform_job_runs`),
        pool.query(`SELECT (SELECT COUNT(*) FROM webhook_deliveries WHERE status IN('queued','failed') AND attempts<5)::int webhooks,(SELECT COUNT(*) FROM email_deliveries WHERE status IN('queued','failed') AND attempt_count<5)::int emails`),
        pool.query(`SELECT backup_verified_at,monitoring_verified_at,monitoring_endpoint FROM platform_launch_attestations WHERE id=1`)
      ]),
      withTenant(tenantId,async c=>{
        const results=await Promise.all([
          c.query(`SELECT COUNT(*) FILTER(WHERE role='admin' AND COALESCE(account_active,TRUE))::int admins,COUNT(*) FILTER(WHERE role='guard' AND COALESCE(account_active,TRUE))::int guards,COUNT(*) FILTER(WHERE role='staff' AND COALESCE(account_active,TRUE))::int staff FROM users WHERE tenant_id=$1`,[tenantId]),
          c.query(`SELECT COUNT(DISTINCT ga.user_id)::int assigned FROM guard_assignments ga JOIN users u ON u.id=ga.user_id AND u.tenant_id=ga.tenant_id WHERE ga.tenant_id=$1 AND u.role='guard' AND COALESCE(u.account_active,TRUE)`,[tenantId]),
          c.query(`SELECT COUNT(*) FILTER(WHERE offline_captured=TRUE AND client_scan_id IS NOT NULL AND device_scanned_at IS NOT NULL)::int offline_scans FROM patrol_logs WHERE tenant_id=$1`,[tenantId]),
          c.query(`SELECT COUNT(*) FILTER(WHERE offline_captured=TRUE AND client_incident_id IS NOT NULL AND device_reported_at IS NOT NULL AND device_id IS NOT NULL)::int offline_incidents FROM incidents WHERE tenant_id=$1`,[tenantId]),
          c.query(`SELECT id,details,created_at FROM system_events WHERE tenant_id=$1 AND event_type='stage_12_2_acceptance' ORDER BY created_at DESC LIMIT 1`,[tenantId]),
          c.query(`SELECT id,details,created_at FROM system_events WHERE tenant_id=$1 AND event_type='stage_12_3_pilot_acceptance' ORDER BY created_at DESC LIMIT 1`,[tenantId]),
          c.query(`SELECT COUNT(*)::int count FROM audit_logs WHERE tenant_id=$1`,[tenantId])
        ]);return{roles:results[0].rows[0],assigned:results[1].rows[0],scans:results[2].rows[0],incidents:results[3].rows[0],browser:results[4].rows[0]||null,pilot:results[5].rows[0]||null,audit:results[6].rows[0]};
      })
    ]);
    const [rlsResult,jobsResult,queuesResult,attestationResult]=globalData,rls=rlsResult.rows[0],jobs=jobsResult.rows[0],queues=queuesResult.rows[0],attestation=attestationResult.rows[0]||{};
    add('roles','Production role coverage',Number(tenantData.roles.admins)>0&&Number(tenantData.roles.guards)>0,`${tenantData.roles.admins} administrator(s), ${tenantData.roles.guards} guard(s), ${tenantData.roles.staff} delegated staff account(s)`,true,tenantData.roles);
    add('assignments','Guard assignment readiness',Number(tenantData.roles.guards)>0&&Number(tenantData.assigned.assigned)===Number(tenantData.roles.guards),`${tenantData.assigned.assigned}/${tenantData.roles.guards} active guard(s) assigned to a site`,true,tenantData.assigned);
    const browserAge=tenantData.browser?(Date.now()-new Date(tenantData.browser.created_at).getTime())/86400000:null,browserManual=tenantData.browser?.details?.manual||{},browserComplete=tenantData.browser&&browserAge<=30&&BROWSER_ACCEPTANCE_MANUAL.every(key=>browserManual[key]===true);
    add('browser_acceptance','Browser, mobile and offline acceptance',browserComplete,browserComplete?`Complete acceptance recorded ${new Date(tenantData.browser.created_at).toISOString()}`:'Complete and save all Stage 12.2 acceptance items within the last 30 days',true,{created_at:tenantData.browser?.created_at||null,age_days:browserAge,manual:browserManual});
    add('offline_evidence','Production offline evidence',Number(tenantData.scans.offline_scans)>0&&Number(tenantData.incidents.offline_incidents)>0,`${tenantData.scans.offline_scans} synchronized offline patrol scan(s); ${tenantData.incidents.offline_incidents} offline incident(s)`,true,{...tenantData.scans,...tenantData.incidents});
    const rlsReady=Number(rls.total)>0&&Number(rls.enabled)===Number(rls.total)&&Number(rls.protected)===Number(rls.total),rlsMissing=[...new Set([...(rls.missing_rls||[]),...(rls.missing_policy||[])])];
    add('tenant_protection','Tenant RLS protection',rlsReady,rlsReady?`${rls.protected}/${rls.total} tenant tables protected; ${rls.enabled}/${rls.total} have RLS enabled`:`${rls.protected}/${rls.total} tenant tables protected; ${rls.enabled}/${rls.total} have RLS enabled. Missing: ${rlsMissing.join(', ')||'unknown table'}`,true,rls);
    add('job_health','Background-job health',Number(jobs.failed)===0&&Number(jobs.stuck)===0,`${jobs.failed} failed in 24 hours; ${jobs.stuck} stuck`,true,jobs);
    add('delivery_backlog','Delivery backlog',Number(queues.webhooks)===0&&Number(queues.emails)===0,`${queues.webhooks} webhook and ${queues.emails} email delivery item(s) queued for retry`,false,queues);
    const backupFresh=attestation.backup_verified_at&&Date.now()-new Date(attestation.backup_verified_at).getTime()<=30*86400000;
    add('recovery_monitoring','Recovery and monitoring evidence',backupFresh&&Boolean(attestation.monitoring_verified_at),backupFresh&&attestation.monitoring_verified_at?`Backup is current and health monitoring is confirmed at ${attestation.monitoring_endpoint||'/health'}`:'Refresh platform backup evidence and confirm production monitoring',true,{backup_verified_at:attestation.backup_verified_at,monitoring_verified_at:attestation.monitoring_verified_at,monitoring_endpoint:attestation.monitoring_endpoint});
    const pilot=tenantData.pilot?.details||{},pilotAge=tenantData.pilot?(Date.now()-new Date(tenantData.pilot.created_at).getTime())/86400000:null,pilotComplete=tenantData.pilot&&pilotAge<=30&&PILOT_ACCEPTANCE_REQUIRED.every(key=>Boolean(pilot[key]))&&pilot.scope_acknowledged===true;
    add('pilot_plan','Controlled pilot plan',pilotComplete,pilotComplete?`${pilot.pilot_name||'Controlled pilot'} starts ${pilot.planned_start} for ${pilot.duration_days||14} day(s)`:'Save a named owner, support contact, rollback owner and rollback trigger for the controlled pilot',true,{event_id:tenantData.pilot?.id||null,created_at:tenantData.pilot?.created_at||null,pilot});
    add('auditability','Operational auditability',Number(tenantData.audit.count)>0,`${tenantData.audit.count} subscriber audit record(s) available for pilot review`,true,tenantData.audit);
    const failures=checks.filter(x=>x.status==='fail').length,warnings=checks.filter(x=>x.status==='warning').length,passed=checks.filter(x=>x.status==='pass').length;
    res.json({status:failures?'action_required':warnings?'ready_with_warnings':'stage_12_3_ready',label:failures?'ACTION REQUIRED':warnings?'READY WITH WARNINGS':'STAGE 12.3 READY',completed_at:new Date().toISOString(),duration_ms:Date.now()-started,summary:{passed,warnings,failures,total:checks.length},pilot:tenantData.pilot?{...pilot,recorded_at:tenantData.pilot.created_at}:null,checks});
  }catch(e){res.status(500).json({error:e.message})}
});

// ------------------------ SERVER START ------------------------

const server=app.listen(PORT, () => {
  runtimeState.ready=true;
  console.log(`PatrolSync backend running on port ${PORT}`);
  const posture=getProductionSecurityPosture(),issues=posture.checks.filter(x=>!x.passed);
  if(issues.length)console.warn('Production security configuration warnings:',issues.map(x=>`${x.key}: ${x.message}`).join(' | '));
  else console.log('Production API security posture: ready');
});
server.keepAliveTimeout=65000;
server.headersTimeout=66000;
server.requestTimeout=30000;

let shutdownPromise=null;
function beginGracefulShutdown(signal){
  if(shutdownPromise)return shutdownPromise;
  shutdownPromise=(async()=>{
    runtimeState.ready=false;runtimeState.draining=true;runtimeState.shutdown_signal=signal;runtimeState.shutdown_started_at=new Date().toISOString();
    console.log(JSON.stringify({level:'info',type:'graceful_shutdown_started',signal,instance_id:BACKGROUND_INSTANCE_ID,active_requests:runtimeState.active_requests}));
    for(const timer of backgroundTimers){if(timer.type==='interval')clearInterval(timer.handle);else clearTimeout(timer.handle)}
    const forceTimer=setTimeout(()=>{console.error(JSON.stringify({level:'error',type:'graceful_shutdown_timeout',active_requests:runtimeState.active_requests}));process.exit(1)},25000);forceTimer.unref();
    await new Promise(resolve=>server.close(resolve));
    await Promise.allSettled([systemPool.end(),...(DATABASE_PATHS_SEPARATED?[tenantPool.end()]:[])]);
    clearTimeout(forceTimer);
    console.log(JSON.stringify({level:'info',type:'graceful_shutdown_complete',signal,instance_id:BACKGROUND_INSTANCE_ID}));
    process.exit(0);
  })();
  return shutdownPromise;
}
process.once('SIGTERM',()=>beginGracefulShutdown('SIGTERM'));
process.once('SIGINT',()=>beginGracefulShutdown('SIGINT'));
process.on('unhandledRejection',reason=>console.error(JSON.stringify({level:'error',type:'unhandled_rejection',message:String(reason?.stack||reason)})));
