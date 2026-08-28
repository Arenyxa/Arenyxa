import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));const args=process.argv.slice(2);let port=3100;for(let i=0;i<args.length;i++){if(args[i]==='--port'&&args[i+1])port=Number(args[i+1])||port;else if(args[i].startsWith('--port='))port=Number(args[i].split('=')[1])||port;}
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.txt':'text/plain; charset=utf-8','.geojson':'application/geo+json; charset=utf-8'};
const server=http.createServer((req,res)=>{let raw;try{raw=decodeURIComponent((req.url||'/').split('?')[0]);}catch{res.writeHead(400);res.end('Bad Request');return;}const rel=raw==='/'?'index.html':raw.replace(/^\/+/,''),resolved=path.resolve(root,rel);if(!resolved.startsWith(root+path.sep)&&resolved!==path.join(root,'index.html')){res.writeHead(403);res.end('Forbidden');return;}fs.stat(resolved,(e,st)=>{if(e||!st.isFile()){res.writeHead(404);res.end('Not Found');return;}res.setHeader('Content-Type',mime[path.extname(resolved).toLowerCase()]||'application/octet-stream');res.setHeader('Cache-Control','no-cache');fs.createReadStream(resolved).pipe(res);});});
server.listen(port,'0.0.0.0',()=>console.log(`Arenyxa V9.1 Hybrid Flagship running at http://localhost:${port}/`));
