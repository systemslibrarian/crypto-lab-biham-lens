import {ISBOX,encrypt80} from './present.js';
const MASK80=(1n<<80n)-1n;
export function unwind(register:bigint,fromRound=32){let x=register;for(let round=fromRound-1;round>=1;round--){x^=BigInt(round)<<15n;x=(x&((1n<<76n)-1n))|(BigInt(ISBOX[Number(x>>76n)])<<76n);x=((x>>61n)|(x<<19n))&MASK80;}return x;}
export interface KnownPair{plaintext:bigint;ciphertext:bigint}
export function recoverFromK32(k32:bigint,pair:KnownPair,onProgress:(tried:number,survivors:number)=>void=()=>{}){
 if(k32<0n||k32>=(1n<<64n))throw Error('K32 must be 64 bits.');const survivors:bigint[]=[];let tried=0;
 for(let low=0;low<65536;low++){const candidate=unwind((k32<<16n)|BigInt(low));if(encrypt80(pair.plaintext,candidate)===pair.ciphertext)survivors.push(candidate);tried++;if(tried%256===0)onProgress(tried,survivors.length);}return {tried,survivors};
}
