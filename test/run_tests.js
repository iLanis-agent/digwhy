// Cross-check engine.js parser against the Python oracle on real dig captures.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const D = require('../engine.js');

const corpusDir = 'test/corpus';
const oracle = JSON.parse(execFileSync('python3', ['test/oracle.py', corpusDir]).toString());
let fails = 0, checked = 0;
function eq(a, b, label) {
  checked++;
  if (JSON.stringify(a) !== JSON.stringify(b)) { fails++; if (fails <= 6) console.log('MISMATCH', label, '\n js:', JSON.stringify(a), '\n py:', JSON.stringify(b)); }
}
for (const fn of Object.keys(oracle)) {
  const text = fs.readFileSync(path.join(corpusDir, fn), 'utf8');
  const js = D.parseDig(text);
  const py = oracle[fn];
  for (const k of ['version', 'opcode', 'status', 'id', 'flags', 'counts', 'opt', 'question', 'answer', 'authority', 'additional', 'queryTime', 'server', 'size']) {
    eq(js[k], py[k], fn + ' ' + k);
  }
}
// Explanation sanity on the corpus
const nx = D.parseDig(fs.readFileSync(path.join(corpusDir, 'nxdomain.txt'), 'utf8'));
const notesNx = D.explain(nx);
checked++;
if (!notesNx.some(n => n.text.includes('NXDOMAIN'))) { fails++; console.log('EXPLAIN FAIL nxdomain'); }
const cn = D.parseDig(fs.readFileSync(path.join(corpusDir, 'cname-chain.txt'), 'utf8'));
const notesCn = D.explain(cn);
checked++;
if (!notesCn.some(n => n.text.includes('CNAME chain'))) { fails++; console.log('EXPLAIN FAIL cname', JSON.stringify(notesCn)); }
const nd = D.parseDig(fs.readFileSync(path.join(corpusDir, 'caa.txt'), 'utf8'));
const notesNd = D.explain(nd);
checked++;
if (!notesNd.some(n => n.text.includes('NODATA'))) { fails++; console.log('EXPLAIN FAIL nodata', JSON.stringify(notesNd)); }
const nm = D.parseDig(fs.readFileSync(path.join(corpusDir, 'nodata-mx.txt'), 'utf8'));
const notesNm = D.explain(nm);
checked++;
if (!notesNm.some(n => n.text.includes('Null MX'))) { fails++; console.log('EXPLAIN FAIL nullmx', JSON.stringify(notesNm)); }
const ab = D.parseDig(fs.readFileSync(path.join(corpusDir, 'a-basic.txt'), 'utf8'));
const notesAb = D.explain(ab);
checked++;
if (!notesAb.some(n => n.text.includes('No aa flag'))) { fails++; console.log('EXPLAIN FAIL aa', JSON.stringify(notesAb)); }
checked++;
if (!notesAb.some(n => n.text.includes('Multiple address'))) { fails++; console.log('EXPLAIN FAIL multi', JSON.stringify(notesAb)); }
console.log(`checked=${checked} fails=${fails}`);
process.exit(fails ? 1 : 0);
