-- SPDX-License-Identifier: Apache-2.0
-- bhf Lua fork-server driver. A debug.sethook("l") line hook records edge
-- coverage into the shared BHF_COV_SHM map. Speaks the BHF_FRAMED protocol
-- (matches c_runtime/bhf_driver.c and the Ruby/Perl drivers): fd 1 control pipe,
-- fd 0 input pipe ({u32 LE len, bytes}). A finding errors -> stderr marker + exit 86
-- (no sync byte); an expected rejection (a bad-argument / index-nil error) is
-- swallowed. No third-party fuzzer.

local FINDING_HALT = 86
local TARGET_MODULE = os.getenv("BHF_TARGET_MODULE") or ""

-- ---- Coverage: a line hook folded into a 64KB edge bitmap. ----
-- Line events cost a hook call each, so only the target's own chunks get them:
-- a call/return hook notes which chunk runs and turns the line events on while
-- it is a target chunk (under BHF_TRACE_PREFIX, not this driver or the
-- harness) and off elsewhere. Each chunk gets an integer id and its hash once.
local COV_BITS = 1 << 16
local COV_MASK = COV_BITS - 1
local LINE_IDS = 1 << 24                         -- covered key: chunk id * LINE_IDS + line
local cov = {}                                   -- sparse byte map: idx -> count
local dirty = {}                                 -- indices changed since last flush
local cov_prev = 0
local cov_prefix = os.getenv("BHF_TRACE_PREFIX") or ""
local covered = {}                               -- covered key -> true
local covered_dumped = 0
local file_sized = false
local getinfo, sethook = debug.getinfo, debug.sethook

local function fnv_prefix(str)
  local h = 0x811c9dc5
  for k = 1, #str do
    h = ((h ~ str:byte(k)) * 0x01000193) & 0xFFFFFFFF
  end
  return h
end

-- chunk_id[source] is the target chunk's id, or false for any other chunk.
local chunk_id, chunk_path, chunk_hash = {}, {}, {}
local own_sources = {}                           -- this driver and the harness

local function chunk_of(source)
  local id = chunk_id[source]
  if id ~= nil then return id end
  id = false
  if source and source:sub(1, 1) == "@" and not own_sources[source] then
    local path = source:sub(2)
    if cov_prefix == "" or path:sub(1, #cov_prefix) == cov_prefix then
      id = #chunk_path + 1
      chunk_path[id] = path
      chunk_hash[id] = fnv_prefix(path)
    end
  end
  chunk_id[source] = id
  return id
end

local cur_id, cur_hash, cur_fn, mask = false, 0, nil, ""
local hook

-- A long loop over edges the map already holds teaches nothing, and each line
-- event costs a hook call: after QUIET_LIMIT line events in a row with no new
-- edge, the function they ran in pauses (its line events stop, re-entering it
-- keeps them stopped), and a count hook resumes them every COUNT_WINDOW
-- instructions, so a loop that reaches new code is still traced. Calling a
-- different target function resumes them too. (lua_sethook walks the whole
-- call stack, so the mask is changed only when it has to be.)
local QUIET_LIMIT, COUNT_WINDOW = 256, 100000
local quiet, paused_fn = 0, nil

local function line_event(line)
  covered[cur_id * LINE_IDS + line] = true
  local h = ((cur_hash ~ (line & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  h = ((h ~ ((line >> 8) & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  local block = h & COV_MASK
  local idx = (cov_prev ~ block) & COV_MASK
  local v = cov[idx] or 0
  if v < 0xFF then
    cov[idx] = v + 1
    dirty[idx] = true
  end
  cov_prev = (block >> 1) & COV_MASK
  if v == 0 then
    quiet = 0
  else
    quiet = quiet + 1
    if quiet >= QUIET_LIMIT then
      paused_fn = cur_fn
      mask = "cr"
      sethook(hook, mask, COUNT_WINDOW)
    end
  end
end

-- Line events while function `fn` of target chunk `id` runs, unless it is
-- paused; only calls and returns elsewhere.
local function switch_to(id, fn)
  cur_id, cur_fn = id, fn
  if id then cur_hash = chunk_hash[id] end
  local want = (id and fn ~= paused_fn) and "crl" or "cr"
  if want ~= mask then
    mask = want
    quiet = 0
    sethook(hook, mask, (want == "cr" and paused_fn) and COUNT_WINDOW or 0)
  end
end

hook = function(event, line)
  if event == "line" then
    if cur_id then line_event(line) end
    return
  end
  if event == "count" then
    paused_fn, quiet = nil, 0
    if cur_id then
      mask = "crl"
      sethook(hook, mask)
    end
    return
  end
  -- On a return, the function that runs next is the caller (level 3). A C
  -- function has no lines: calling one changes nothing.
  local info = getinfo(event == "return" and 3 or 2, "Sf")
  if not info or (event ~= "return" and info.what == "C") then return end
  switch_to(chunk_of(info.source), info.func)
end

local function hook_on()
  mask, quiet, paused_fn = "", 0, nil
  switch_to(false, nil)
end
local function hook_off() sethook(); mask = "" end

local function reset_prev() cov_prev = 0 end

-- Write only the bytes that changed since the last flush into the shared 64KB edge
-- bitmap (the engine mmaps it read-only). The file is pre-sized to 64KB once; the
-- map is cumulative (counts only grow), so per-input dirty-writes suffice and avoid
-- rebuilding the whole image each exec.
local function flush_cov()
  local path = os.getenv("BHF_COV_SHM")
  if not path or path == "" then return end
  local f = io.open(path, "r+b") or io.open(path, "wb")
  if not f then return end
  if not file_sized then
    f:seek("set", COV_BITS - 1)
    f:write("\0")
    file_sized = true
  end
  for idx in pairs(dirty) do
    f:seek("set", idx)
    f:write(string.char(cov[idx]))
    dirty[idx] = nil
  end
  f:close()
end

local function dump_covered()
  local path = os.getenv("BHF_COVERED_LINES")
  if not path or path == "" then return end
  local n = 0
  for _ in pairs(covered) do n = n + 1 end
  if n == covered_dumped then return end
  local keys = {}
  for key in pairs(covered) do
    keys[#keys + 1] = chunk_path[key // LINE_IDS] .. ":" .. (key % LINE_IDS)
  end
  table.sort(keys)
  local f = io.open(path .. ".tmp", "w")
  if not f then return end
  f:write(table.concat(keys, "\n"))
  f:close()
  os.rename(path .. ".tmp", path)
  covered_dumped = n
end

-- ---- Finding classification (FP-avoidant, like the Ruby/Python/Perl lanes). ----
-- Only high-confidence bug-class errors are findings; Lua's normal input-rejection
-- errors ("attempt to index a nil value", "bad argument", "attempt to call") are
-- suppressed. `msg` is the error value stringified.
local function bug_cwe(msg)
  msg = tostring(msg)
  local lower = msg:lower()
  -- A target-namespaced error object (rare in Lua) is a declared rejection.
  if TARGET_MODULE ~= "" and lower:find(TARGET_MODULE:lower(), 1, true) and lower:find("reject") then
    return nil
  end
  if lower:find("stack overflow", 1, true) then return "CWE-674" end
  if lower:find("not enough memory", 1, true) or lower:find("out of memory", 1, true) then
    return "CWE-789"
  end
  -- Lua 5.4 integer divide/modulo by zero: "attempt to perform 'n//0'" / "'n%%0'".
  if lower:find("'n//0'", 1, true) or lower:find("'n%%0'", 1, true)
      or lower:find("divide by zero", 1, true) then
    return "CWE-369"
  end
  if lower:find("assert", 1, true) or lower:find("unreachable", 1, true)
      or lower:find("invariant", 1, true) or lower:find("should not happen", 1, true) then
    return "CWE-617"
  end
  return nil -- generic Lua error = normal input rejection, suppressed
end

local control -- fd 1 handle, saved before stdout redirect

-- The target frames at the last error, innermost first, as
-- `function @ file:line` (at most 5): the error handler records them before
-- the stack unwinds.
local error_frames = {}

local function capture_frames(err)
  hook_off()
  local frames = {}
  for level = 2, 64 do
    local info = getinfo(level, "Sln")
    if not info then break end
    if chunk_of(info.source) and info.currentline and info.currentline > 0 then
      frames[#frames + 1] = (info.name or "?") .. " @ " .. info.source:sub(2) .. ":" .. info.currentline
      if #frames >= 5 then break end
    end
  end
  error_frames = frames
  return err
end

local function report_finding(cwe, msg)
  msg = tostring(msg):gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
  io.stderr:write("== bhf lua finding: " .. cwe .. ": " .. msg .. "\n")
  for _, frame in ipairs(error_frames) do
    io.stderr:write("== bhf frame: " .. frame .. "\n")
  end
  os.exit(FINDING_HALT)
end

local run_one -- the generated harness entry (dofile'd below)

-- How many of the first STATS_WINDOW inputs ended in a nil-value error, which
-- bhf reads back (`lua_nil_errors.json` beside the harness): when nearly all
-- do, the harness is calling the target without the object or state it needs.
local STATS_WINDOW = 1000
local stats_runs, stats_nil_errors, stats_written = 0, 0, false

local function is_nil_error(err)
  local msg = tostring(err)
  return msg:find("a nil value", 1, true) ~= nil or msg:find("compare nil", 1, true) ~= nil
end

local function write_stats()
  -- Only the fuzz loop's own count: a later replay of one input must not
  -- overwrite it.
  if stats_written or stats_runs == 0 or not os.getenv("BHF_FRAMED") then return end
  local harness = os.getenv("BHF_HARNESS") or ""
  local dir = harness:match("^(.*)[/\\]") or "."
  local f = io.open(dir .. "/lua_nil_errors.json", "w")
  if not f then return end
  f:write(string.format('{"executions": %d, "nil_errors": %d}\n', stats_runs, stats_nil_errors))
  f:close()
  stats_written = stats_runs >= STATS_WINDOW
end

local function run_input(data)
  reset_prev()
  hook_on()
  local ok, err = xpcall(run_one, capture_frames, data)
  -- Formatting the error runs no target code worth tracing.
  hook_off()
  if stats_runs < STATS_WINDOW then
    stats_runs = stats_runs + 1
    if not ok and is_nil_error(err) then stats_nil_errors = stats_nil_errors + 1 end
    if stats_runs == STATS_WINDOW then write_stats() end
  end
  if not ok then
    local cwe = bug_cwe(err)
    if cwe then
      write_stats()
      report_finding(cwe, err)
    end
  end
end

local function read_exact(n)
  local buf = {}
  local got = 0
  while got < n do
    local chunk = io.stdin:read(n - got)
    if not chunk or #chunk == 0 then return nil end
    buf[#buf + 1] = chunk
    got = got + #chunk
  end
  return table.concat(buf)
end

-- ---- Load the target harness (returns bhf_run_one). ----
local harness = os.getenv("BHF_HARNESS") or error("BHF_HARNESS unset")
own_sources["@" .. harness] = true
own_sources[getinfo(1, "S").source] = true
-- Load the harness (and the target it loads) with the hook on, so the
-- target's top-level code is covered as before.
hook_on()
run_one = assert(dofile(harness), "harness did not return a run_one function")
hook_off()

if os.getenv("BHF_FRAMED") then
  -- Save the control pipe (fd 1) then redirect stdout/print to /dev/null so the
  -- target's output can't corrupt the sync stream (#427).
  control = io.stdout
  control:setvbuf("no")
  local devnull = io.open("/dev/null", "w")
  if devnull then
    io.output(devnull)
    io.stdout = devnull
  end
  _G.print = function() end
  io.stdin:setvbuf("no")
  control:write("\1") -- ready byte
  local count = 0
  while true do
    local hdr = read_exact(4)
    if not hdr then break end
    local n = string.unpack("<I4", hdr)
    local data = n > 0 and read_exact(n) or ""
    if not data then break end
    run_input(data)
    flush_cov()
    control:write("\1") -- sync byte
    count = count + 1
    -- Exponentially spaced early checkpoints keep short campaigns from losing
    -- all line evidence before the old 512-input checkpoint.
    if (count & (count - 1)) == 0 or (count & 0x1FF) == 0 then
      dump_covered()
      write_stats()
    end
  end
else
  local data
  local arg1 = arg and arg[1]
  if arg1 then
    local f = io.open(arg1, "rb")
    if f then data = f:read("a"); f:close() end
  end
  data = data or io.stdin:read("a") or ""
  run_input(data)
  flush_cov()
end
dump_covered()
write_stats()
