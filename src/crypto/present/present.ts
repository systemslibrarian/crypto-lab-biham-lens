/** PRESENT-80, CHES 2007 §3. Bit 0 is the least significant bit. */
export const SBOX=[12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2] as const;
export const ISBOX=Array.from({length:16},(_,y)=>SBOX.indexOf(y as typeof SBOX[number]));
const MASK64=(1n<<64n)-1n,MASK80=(1n<<80n)-1n;
export const hex=(v:bigint,n=16)=>v.toString(16).toUpperCase().padStart(n,'0');
export function parseHex(text:string,n:number):bigint{if(!new RegExp(`^[a-f0-9]{${n}}$`,'i').test(text))throw Error(`Expected exactly ${n} hexadecimal characters; found ${text.length}.`);return BigInt('0x'+text);}
export function permutation(i:number){return i===63?63:i*16%63;}
export function sBoxLayer(x:bigint,inverse=false):bigint{const table=inverse?ISBOX:SBOX;let y=0n;for(let i=0;i<16;i++)y|=BigInt(table[Number(x>>BigInt(i*4)&15n)])<<BigInt(i*4);return y;}
export function pLayer(x:bigint,inverse=false):bigint{let y=0n;for(let i=0;i<64;i++){const target=inverse?(i===63?63:i*4%63):permutation(i);y|=((x>>BigInt(i))&1n)<<BigInt(target);}return y;}
export function updateKey80(register:bigint,round:number):bigint{
 let x=((register<<61n)|(register>>19n))&MASK80;
 x=(x&((1n<<76n)-1n))|(BigInt(SBOX[Number(x>>76n)])<<76n);
 return x^(BigInt(round)<<15n);
}
export function keySchedule80(key:bigint){if(key<0n||key>MASK80)throw Error('Key is outside 80 bits.');const rows=[];let register=key;for(let round=1;round<=32;round++){rows.push({round,register,key:register>>16n});if(round<32)register=updateKey80(register,round);}return rows;}
export function trace80(plaintext:bigint,key:bigint){if(plaintext<0n||plaintext>MASK64)throw Error('Block is outside 64 bits.');const keys=keySchedule80(key);let state=plaintext;const rows=[];for(let i=0;i<31;i++){const input=state,added=state^keys[i].key,sub=sBoxLayer(added);state=pLayer(sub);rows.push({round:i+1,input,key:keys[i].key,added,sub,permuted:state});}return {rows,ciphertext:state^keys[31].key,finalKey:keys[31].key};}
// Byte tables preserve the exact sBoxLayer/pLayer. Their equality is exhaustively tested.
const SUB=Uint8Array.from({length:256},(_,i)=>(SBOX[i>>>4]<<4)|SBOX[i&15]);
const PH=Array.from({length:8},()=>new Uint32Array(256)),PL=Array.from({length:8},()=>new Uint32Array(256));
for(let b=0;b<8;b++)for(let v=0;v<256;v++){const y=pLayer(BigInt(SUB[v])<<BigInt(b*8));PH[b][v]=Number(y>>32n);PL[b][v]=Number(y&0xffffffffn);}
export function encrypt80(plaintext:bigint,key:bigint):bigint{
 if(plaintext<0n||plaintext>MASK64)throw Error('Block is outside 64 bits.');if(key<0n||key>MASK80)throw Error('Key is outside 80 bits.');
 let hi=Number(plaintext>>32n)>>>0,lo=Number(plaintext&0xffffffffn)>>>0,reg=key;
 for(let round=1;round<=31;round++){hi=(hi^Number(reg>>48n))>>>0;lo=(lo^Number((reg>>16n)&0xffffffffn))>>>0;let h=0,l=0;for(let b=0;b<8;b++){const v=((b<4?lo:hi)>>>((b%4)*8))&255;h^=PH[b][v];l^=PL[b][v];}hi=h>>>0;lo=l>>>0;reg=updateKey80(reg,round);}
 return ((BigInt(hi)<<32n)|BigInt(lo))^(reg>>16n);
}
export function decrypt80(ciphertext:bigint,key:bigint):bigint{const keys=keySchedule80(key);let s=ciphertext^keys[31].key;for(let i=30;i>=0;i--)s=sBoxLayer(pLayer(s,true),true)^keys[i].key;return s;}
// [extension] point: PRESENT-128 needs a separately vectored key schedule.
