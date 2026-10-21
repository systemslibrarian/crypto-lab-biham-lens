import {recoverFromK32,type KnownPair} from './unwind.js';
export interface UnwindRequest{k32:bigint;pair:KnownPair}
self.onmessage=(event:MessageEvent<UnwindRequest>)=>{const {k32,pair}=event.data;try{const start=performance.now();const result=recoverFromK32(k32,pair,(tried,survivors)=>self.postMessage({kind:'progress',tried,survivors}));self.postMessage({kind:'done',...result,elapsedMs:performance.now()-start});}catch(e){self.postMessage({kind:'error',message:(e as Error).message});}};
