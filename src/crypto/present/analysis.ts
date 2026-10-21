import {SBOX,permutation} from './present.js';
export function ddt(){const table=Array.from({length:16},()=>Array(16).fill(0) as number[]);for(let a=0;a<16;a++)for(let x=0;x<16;x++)table[a][SBOX[x]^SBOX[x^a]]++;return {table,max:Math.max(...table.slice(1).flat())};}
const parity=(x:number)=>{let p=0;while(x){p^=x&1;x>>>=1;}return p;};
export function walsh(){return Array.from({length:16},(_,a)=>Array.from({length:16},(_,b)=>{let n=0;for(let x=0;x<16;x++)n+=parity(a&x)===parity(b&SBOX[x])?1:-1;return n;}));}
export function conditions123(){const d=ddt(),w=walsh(),bits=[1,2,4,8],single=bits.flatMap(a=>bits.map(b=>d.table[a][b]));return {ddt:d.table,walsh:w,maxDdt:d.max,maxWalsh:Math.max(...w.slice(1).flatMap(row=>row.slice(1).map(Math.abs))),single,c1:d.max<=4,c2:single.every(x=>x===0),c3:w.slice(1).every(row=>row.slice(1).every(x=>Math.abs(x)<=8))};}
export function pLayerSpread() {
  const sources = Array.from({ length: 16 }, (_, box) =>
    Array.from({ length: 64 }, (_, i) => i)
      .filter(i => Math.floor(permutation(i) / 4) === box)
      .map(i => Math.floor(i / 4)),
  );
  const destinations = Array.from({ length: 16 }, (_, box) =>
    Array.from({ length: 4 }, (_, bit) => Math.floor(permutation(box * 4 + bit) / 4)),
  );
  const input = sources.map(boxes => new Set(boxes).size);
  const output = destinations.map(boxes => new Set(boxes).size);
  const inputGroups = sources.map(boxes => new Set(boxes.map(box => Math.floor(box / 4))).size);
  const outputGroups = destinations.map(boxes => new Set(boxes.map(box => Math.floor(box / 4))).size);
  return {
    input,
    output,
    inputGroups,
    outputGroups,
    observation1: input.every(count => count === 4) && inputGroups.every(count => count === 1),
    observation3: output.every(count => count === 4) && outputGroups.every(count => count === 4),
  };
}
// [extension] point: a characteristic search would require its own independent bound checks.
