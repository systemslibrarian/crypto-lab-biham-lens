// Mutations run only on a committed, clean source baseline. Each is built, killed,
// restored byte-for-byte, rebuilt and tested green before the next begins.
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'); process.chdir(root);
const config = process.env.PLAYWRIGHT_CONFIG;
const browser = title => ['npx', ['playwright','test','e2e/present.spec.ts','--project=chromium','--grep',title,'--workers=1','--retries=0',...(config ? ['--config',config] : [])]];
const build = ['npm',['run','build']];
const run = ([cmd,args]) => spawnSync(cmd,args,{cwd:root,encoding:'utf8',env:{...process.env,CI:'1'}});
const pass = (cmd,label) => { const r=run(cmd); if(r.status!==0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`); return r; };
const hash = () => { const h=createHash('sha256'); const walk=d=>{for(const e of readdirSync(d,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){const p=join(d,e.name); if(e.isDirectory())walk(p);else {h.update(p);h.update(readFileSync(p));}}};walk('dist');return h.digest('hex'); };
const cases = [
  [
    "wrong permutation modulus",
    "src/crypto/present/present.ts",
    "i*16%63",
    "i*16%64",
    [
      "node",
      [
        "--import",
        "tsx",
        "--test",
        "--test-name-pattern",
        "PRESENT four published",
        "src/__tests__/present.test.ts"
      ]
    ]
  ],
  [
    "wrong key rotation",
    "src/crypto/present/present.ts",
    "((register<<61n)|(register>>19n))",
    "((register<<19n)|(register>>61n))",
    [
      "node",
      [
        "--import",
        "tsx",
        "--test",
        "--test-name-pattern",
        "PRESENT four published",
        "src/__tests__/present.test.ts"
      ]
    ]
  ],
  [
    "counter bit 16",
    "src/crypto/present/present.ts",
    "(BigInt(round)<<15n)",
    "(BigInt(round)<<16n)",
    [
      "node",
      [
        "--import",
        "tsx",
        "--test",
        "--test-name-pattern",
        "PRESENT four published",
        "src/__tests__/present.test.ts"
      ]
    ]
  ],
  [
    "fifteen S-box nibbles",
    "src/crypto/present/present.ts",
    "i<16;i++",
    "i<15;i++",
    [
      "node",
      [
        "--import",
        "tsx",
        "--test",
        "--test-name-pattern",
        "PRESENT four published",
        "src/__tests__/present.test.ts"
      ]
    ]
  ],
  [
    "unwind skips inverse S-box",
    "src/crypto/present/unwind.ts",
    "BigInt(ISBOX[Number(x>>76n)])",
    "BigInt(ISBOX.indexOf(ISBOX[Number(x>>76n)]))",
    [
      "node",
      [
        "--import",
        "tsx",
        "--test",
        "--test-name-pattern",
        "PRESENT full 65536",
        "src/__tests__/present.test.ts"
      ]
    ]
  ],
  [
    "half search range",
    "src/crypto/present/unwind.ts",
    "low<65536",
    "low<32768",
    [
      "node",
      [
        "--import",
        "tsx",
        "--test",
        "--test-name-pattern",
        "PRESENT full 65536",
        "src/__tests__/present.test.ts"
      ]
    ]
  ],
  [
    "DDT includes zero row",
    "src/crypto/present/analysis.ts",
    "table.slice(1).flat()",
    "table.flat()",
    [
      "node",
      [
        "--import",
        "tsx",
        "--test",
        "--test-name-pattern",
        "PRESENT S-box conditions",
        "src/__tests__/present.test.ts"
      ]
    ]
  ],
  [
    "neutral recovery verdict",
    "src/present-tab.ts",
    "el('recovery').className=data.survivors.length?'present-alarm':'present-info';el('recovery').dataset.verdict=data.survivors.length?'recovered':'none';",
    "el('recovery').className='present-info';el('recovery').dataset.verdict='neutral';",
    [
      "npx",
      [
        "playwright",
        "test",
        "e2e/present.spec.ts",
        "--project=chromium",
        "--grep",
        "PRESENT negative claim",
        "--workers=1",
        "--retries=0"
      ]
    ]
  ],
  [
    "negative claim deleted",
    "src/present-tab.ts",
    "does not keep the master key secret",
    "has a mathematical property",
    [
      "npx",
      [
        "playwright",
        "test",
        "e2e/present.spec.ts",
        "--project=chromium",
        "--grep",
        "PRESENT negative claim",
        "--workers=1",
        "--retries=0"
      ]
    ]
  ],
  [
    "fixture roundtrip check negated",
    "src/present-tab.ts",
    "checks('fixture-checks',decrypt80(trace.ciphertext,key)===plaintext)",
    "checks('fixture-checks',decrypt80(trace.ciphertext,key)!==plaintext)",
    [
      "npx",
      [
        "playwright",
        "test",
        "e2e/present.spec.ts",
        "--project=chromium",
        "--grep",
        "PRESENT negative claim",
        "--workers=1",
        "--retries=0"
      ]
    ]
  ]
];
for(const c of cases)if(c[4][1].includes('--grep')&&config)c[4][1].push('--config',config);
const dirty=spawnSync('git',['diff','--exit-code','--',...new Set(cases.map(x=>x[1]))],{encoding:'utf8'});
if(dirty.status!==0)throw Error('Commit the source baseline before mutation checks.');
pass(build,'baseline build');const baseline=hash();const evidence=[];
mkdirSync('mutation-logs',{recursive:true});
for(const [name,file,before,after,command] of cases){
 pass(command,`${name}: baseline test`);
 const original=readFileSync(file,'utf8');if(original.split(before).length!==2)throw Error(`${name}: expected one mutation site`);
 let mutant;
 try{
  writeFileSync(file,original.replace(before,after));
  const diff=spawnSync('git',['diff','--',file],{encoding:'utf8'}).stdout;if(!diff.trim())throw Error(`${name}: empty diff`);
  pass(build,`${name}: mutant build`); mutant=hash();if(mutant===baseline)throw Error(`${name}: bundle did not move`);
  const r=run(command);writeFileSync(`mutation-logs/${name.replaceAll(' ','-')}.log`,r.stdout+r.stderr);
  if(r.status===0 || !/expect\(|AssertionError|Error: expect/.test(r.stdout+r.stderr))throw Error(`${name}: no assertion kill\n${r.stdout}\n${r.stderr}`);
  evidence.push({name,sourceDiff:diff,baseline,mutant,namedTest:command[1].includes('--grep') ? command[1][command[1].indexOf('--grep')+1] : command[1][command[1].indexOf('--test-name-pattern')+1],assertionFailure:true,retries:0});
 }finally{writeFileSync(file,original);pass(build,`${name}: restore build`);if(hash()!==baseline)throw Error(`${name}: restored hash differs`);pass(command,`${name}: restored test`);}
 evidence.at(-1).restoredGreen=true;console.log(`${name}: killed; exact artifact restored; owning test green`);
}
writeFileSync('mutation-evidence-present.json',JSON.stringify(evidence,null,2)+'\n');
