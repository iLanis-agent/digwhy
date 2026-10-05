/* DigWhy engine: parse standard `dig` output and explain every line.
   Pure functions, no DOM. Targets the classic dig 9.x text format. */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.DigWhy = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var STATUS = {
    NOERROR: 'No error - the query was answered normally (whether or not records were found).',
    FORMERR: 'Format error - the server could not parse the query.',
    SERVFAIL: 'Server failure - the server hit an internal problem; often DNSSEC validation failing upstream.',
    NXDOMAIN: 'Non-existent domain - the name itself does not exist (authoritatively).',
    NOTIMP: 'Not implemented - the server refuses this query type.',
    REFUSED: 'Refused - the server declines to answer you (policy / ACL).',
    YXDOMAIN: 'Name exists when it should not.',
    YXRRSET: 'RRset exists when it should not.',
    NXRRSET: 'RRset does not exist when it should.',
    NOTAUTH: 'Server not authoritative for the zone.',
    NOTZONE: 'Name not contained in the zone.'
  };

  var FLAGS = {
    qr: 'response (this is an answer, not a query)',
    aa: 'authoritative answer - the server owns this zone; no cache involved',
    tc: 'truncated - the answer did not fit; retry over TCP (dig +tcp)',
    rd: 'recursion desired - you asked the server to chase the answer for you',
    ra: 'recursion available - the server is a recursive resolver',
    ad: 'authentic data - the resolver validated DNSSEC on this answer',
    cd: 'checking disabled - the query asked the resolver to skip DNSSEC validation',
    z: 'reserved bit set (unusual)',
    do: 'DNSSEC OK - the query signaled it accepts DNSSEC records'
  };

  var RRTYPES = {
    A: 'IPv4 address - where the name points',
    AAAA: 'IPv6 address',
    CNAME: 'canonical name - an alias; everything about this name comes from the target',
    MX: 'mail exchange - who accepts email for the domain (lower preference = tried first)',
    TXT: 'text - usually SPF, DKIM, or verification tokens',
    SOA: 'start of authority - zone metadata: primary NS, admin contact, serial, timers',
    NS: 'nameserver - who is authoritative for the zone',
    PTR: 'pointer - reverse lookup, address back to name',
    SRV: 'service locator - host and port for a named service',
    CAA: 'certificate authority authorization - which CAs may issue certs for this name',
    DS: 'delegation signer - DNSSEC: hash of the child zone\'s key, published by the parent',
    DNSKEY: 'DNS public key used to validate signatures',
    RRSIG: 'DNSSEC signature over an RRset',
    NSEC: 'DNSSEC proof of non-existence (the gap between names)',
    NSEC3: 'hashed variant of NSEC',
    HTTPS: 'HTTPS service binding - modern SRV-like record (RFC 9460)',
    SVCB: 'service binding - generic form of HTTPS',
    DNAME: 'delegation name - like CNAME but for an entire subtree',
    NAPTR: 'naming authority pointer - rewrite rules, mostly VoIP',
    HINFO: 'host info (historic)',
    OPT: 'pseudo-record carrying EDNS options, never part of the zone'
  };

  var CLASSES = { IN: 'internet (the only class you will meet in practice)', CH: 'CHAOS - server trivia like version.bind', HS: 'Hesiod (historic)' };

  function parseDig(text) {
    var lines = String(text == null ? '' : text).split(/\r?\n/);
    var out = {
      version: null, opcode: null, status: null, id: null, flags: [], counts: {},
      opt: null, question: [], answer: [], authority: [], additional: [],
      queryTime: null, server: null, when: null, size: null,
      warnings: [], rawSections: {}
    };
    var section = null;
    var i, line;
    for (i = 0; i < lines.length; i++) {
      line = lines[i];
      var m;
      if ((m = /^; <<>> DiG (\S+)/.exec(line))) { out.version = m[1]; continue; }
      if ((m = /^;; ->>HEADER<<- opcode: (\S+), status: (\S+), id: (\d+)/.exec(line))) {
        out.opcode = m[1]; out.status = m[2]; out.id = parseInt(m[3], 10); continue;
      }
      if ((m = /^;; flags: ([^;]*); QUERY: (\d+), ANSWER: (\d+), AUTHORITY: (\d+), ADDITIONAL: (\d+)/.exec(line))) {
        out.flags = m[1].trim().split(/\s+/).filter(Boolean);
        out.counts = { query: +m[2], answer: +m[3], authority: +m[4], additional: +m[5] };
        continue;
      }
      if (/^;; OPT PSEUDOSECTION:/.test(line)) { section = 'opt'; continue; }
      if ((m = /^; EDNS: version: (\d+), flags:([^;]*); udp: (\d+)/.exec(line))) {
        out.opt = { version: +m[1], flags: m[2].trim().split(/\s+/).filter(Boolean), udp: +m[3] };
        continue;
      }
      if (/^;; QUESTION SECTION:/.test(line)) { section = 'question'; continue; }
      if (/^;; ANSWER SECTION:/.test(line)) { section = 'answer'; continue; }
      if (/^;; AUTHORITY SECTION:/.test(line)) { section = 'authority'; continue; }
      if (/^;; ADDITIONAL SECTION:/.test(line)) { section = 'additional'; continue; }
      if ((m = /^;; Query time: (\d+) msec/.exec(line))) { out.queryTime = +m[1]; section = null; continue; }
      if ((m = /^;; SERVER: (\S+)/.exec(line))) { out.server = m[1]; continue; }
      if ((m = /^;; WHEN: (.+)$/.exec(line))) { out.when = m[1].trim(); continue; }
      if ((m = /^;; MSG SIZE\s+rcvd: (\d+)/.exec(line))) { out.size = +m[1]; continue; }
      if (!section || section === 'opt') continue;
      var rm;
      if (section === 'question') {
        rm = /^;(\S+)\s+\t*\s*(\w+)\s+(\w+)/.exec(line.replace(/\t/g, ' '));
        if (rm) {
          out.question.push({ name: rm[1], cls: rm[2], type: rm[3] });
        }
        continue;
      }
      rm = /^(\S+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(.*)$/.exec(line.replace(/\t/g, ' ').replace(/\s+/g, ' ').trim());
      if (rm) {
        out[section].push({ name: rm[1], ttl: +rm[2], cls: rm[3], type: rm[4], rdata: rm[5].trim() });
      } else if (line.trim() && !/^;;/.test(line.trim())) {
        out.warnings.push('Unparsed line in ' + section + ': "' + line.trim().slice(0, 60) + '"');
      }
    }
    if (out.status === null) out.warnings.push('No HEADER line found - is this really dig output?');
    return out;
  }

  function explain(parsed) {
    var notes = [];
    var p = parsed;
    if (p.status) {
      var sev = (p.status === 'NOERROR') ? 'ok' : 'bad';
      notes.push({ sev: sev, text: 'Status ' + p.status + ': ' + (STATUS[p.status] || 'uncommon status - check the RFC.') });
    }
    if (p.status === 'NXDOMAIN') {
      notes.push({ sev: 'bad', text: 'The name does not exist, full stop. The AUTHORITY section should carry the parent zone\'s SOA as proof - that is the negative answer you cache.' });
    }
    if (p.counts.answer === 0 && p.status === 'NOERROR') {
      notes.push({ sev: 'warn', text: 'NODATA: the name exists, but it has no record of the type you asked for. The SOA in AUTHORITY is the proof. This is not NXDOMAIN - other types may exist.' });
    }
    if (p.flags.indexOf('tc') >= 0) {
      notes.push({ sev: 'warn', text: 'The answer was truncated (tc). What you see is partial - re-run with +tcp to get everything.' });
    }
    if (p.flags.indexOf('aa') < 0 && p.counts.answer > 0) {
      notes.push({ sev: 'info', text: 'No aa flag: this answer came from a resolver\'s cache or recursion, not from the authoritative server. TTLs shown are what is left, not what the zone set.' });
    }
    if (p.flags.indexOf('ad') >= 0) {
      notes.push({ sev: 'ok', text: 'ad flag: the resolver DNSSEC-validated this answer. ( dig +adflag is now default in dig 9.18. )' });
    }
    // CNAME chain detection
    var cnames = p.answer.filter(function (r) { return r.type === 'CNAME'; });
    if (cnames.length > 0) {
      var chain = [];
      var byName = {};
      p.answer.forEach(function (r) { byName[r.name] = r; });
      var cur = cnames[0].name;
      var guard = 0;
      while (byName[cur] && guard < 10) {
        var rec = byName[cur];
        if (rec.type === 'CNAME') { chain.push(rec.name + ' -> ' + rec.rdata); cur = rec.rdata; if (!cur.endsWith('.')) cur += '.'; }
        else { chain.push(rec.name + ' = ' + rec.rdata + ' (' + rec.type + ')'); break; }
        guard++;
      }
      notes.push({ sev: 'info', text: 'CNAME chain: ' + chain.join(' -> ') + '. Resolvers chase the whole chain for you; each hop must be answered.' });
    }
    var nullMx = p.answer.filter(function (r) { return r.type === 'MX' && /^0\s+\.$/.test(r.rdata); });
    if (nullMx.length > 0) {
      notes.push({ sev: 'info', text: 'Null MX ("0 ."): this domain formally declares it accepts no email (RFC 7505). Senders should bounce immediately instead of retrying.' });
    }
    if (p.counts.answer > 1) {
      var types = {};
      p.answer.forEach(function (r) { types[r.type] = (types[r.type] || 0) + 1; });
      if (types.A > 1 || types.AAAA > 1) {
        notes.push({ sev: 'info', text: 'Multiple address records: clients pick one (roughly round-robin per resolver rotation). This is the cheap form of load balancing.' });
      }
    }
    if (p.opt && p.opt.udp && p.size && p.size > p.opt.udp) {
      notes.push({ sev: 'warn', text: 'Response (' + p.size + ' bytes) exceeded the advertised UDP buffer (' + p.opt.udp + ') - that is what the tc flag / TCP retry is for.' });
    }
    if (p.queryTime != null && p.queryTime > 300) {
      notes.push({ sev: 'info', text: p.queryTime + ' msec is slow for DNS - expect single digits from a warm cache; hundreds suggests a distant resolver or a cold, deep chain.' });
    }
    return notes;
  }

  function explainRecord(r) {
    switch (r.type) {
      case 'A': return 'IPv4 address of ' + r.name;
      case 'AAAA': return 'IPv6 address';
      case 'CNAME': return r.name + ' is an alias - resolution continues at ' + r.rdata;
      case 'MX': {
        var m = r.rdata.split(/\s+/);
        if (m[0] === '0' && m[1] === '.') return 'null MX - domain accepts no email (RFC 7505)';
        return 'mail for this domain goes to ' + (m.slice(1).join(' ') || '?') + ' (preference ' + m[0] + ', lower wins)';
      }
      case 'NS': return 'authoritative nameserver for this zone';
      case 'PTR': return 'reverse name for this address';
      case 'TXT': return r.rdata.indexOf('v=spf1') !== -1 ? 'SPF record: which servers may send mail for this domain' : 'free-form text (verification tokens, SPF, DKIM policies)';
      case 'SOA': return 'start of authority: primary NS, admin mailbox (first dot = @), serial, refresh/retry/expire timers, negative-cache TTL';
      case 'CAA': return 'which certificate authorities may issue TLS certs for this domain';
      case 'RRSIG': return 'DNSSEC signature over a record set';
      case 'DS': return 'delegation signer: hash of the child zone key, published by the parent';
      case 'DNSKEY': return 'public key used to verify this zone\'s RRSIGs';
      case 'SRV': return 'service location: priority, weight, port, target';
      default: return '';
    }
  }

  return { STATUS: STATUS, FLAGS: FLAGS, RRTYPES: RRTYPES, CLASSES: CLASSES, parseDig: parseDig, explain: explain, explainRecord: explainRecord };
});
