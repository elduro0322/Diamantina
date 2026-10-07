/* =====================================================================
   Diamantina – conexión con Firebase
   1) Pega aquí la configuración de tu app web de Firebase
      (Consola Firebase → ⚙️ Configuración del proyecto → Tus apps → Web).
   El dueño se reconoce por las reglas de Firestore (tu correo está en las reglas,
   no en este archivo público). Para entrar como dueño abre tudominio.com/?owner
   ===================================================================== */
const FIREBASE_CONFIG = {
  apiKey: "AIzaSyBjRFR9IpFjcV_rJGJ_jWPOB2rrFNXSS40",
  authDomain: "diamantinagame-d2c79.firebaseapp.com",
  projectId: "diamantinagame-d2c79",
  storageBucket: "diamantinagame-d2c79.firebasestorage.app",
  messagingSenderId: "111786109431",
  appId: "1:111786109431:web:c975d20a63ce35830166f2"
};

// Captcha de AdsLab activo (necesita las funciones de Netlify del repositorio)
window.DIAMANTINA_CAPTCHA = true;

/* ---------- No hace falta tocar nada debajo de esta línea ---------- */
(function(){
  try{
    if(typeof firebase==="undefined") { console.warn("Firebase no configurado: el juego funciona sin base de datos."); return; }
    firebase.initializeApp(FIREBASE_CONFIG);
    const fdb=firebase.firestore(); fdb.settings({ignoreUndefinedProperties:true});
    const fauth=firebase.auth();
    const authReady=new Promise(res=>{
      const off=fauth.onAuthStateChanged(async u=>{
        if(u){ off(); res(u); return; }
        try{ await fauth.signInAnonymously(); }catch(e){ console.error(e); off(); res(null); }
      });
    });
    // Short cooperative lease (same behaviour as the Claude database "acquire")
    firebase.firestore.DocumentReference.prototype.acquire=async function(o){
      o=o||{}; const ttl=o.ttlMs||30000, holder=String(o.holder||""), ref=this;
      try{
        return await fdb.runTransaction(async tx=>{
          const s=await tx.get(ref), L=s.exists?(s.data()||{})._lease:null, now=Date.now();
          if(L&&L.until>now&&L.holder!==holder) return {acquired:false};
          tx.set(ref,Object.assign({},o.data||{},{_lease:{holder,until:now+ttl}}),{merge:true});
          return {acquired:true,holder};
        });
      }catch(e){ return {acquired:false}; }
    };
    // Owner = Google account allowed by the Firestore rules (prizes/ is owner-only)
    let ownerCache=null;
    const isOwner=async()=>{ const c=fauth.currentUser; if(!c||c.isAnonymous) return false; if(ownerCache!==null) return ownerCache;
      try{ await fdb.doc("prizes/_owner_check").get(); ownerCache=true; }catch(e){ ownerCache=false; } return ownerCache; };
    window.claude={ use: async name=>{
      const u=await authReady; if(!u) return null;
      if(name==="db") return fdb;
      if(name==="user") return { id: async()=>fauth.currentUser?fauth.currentUser.uid:null, isOwner: ()=>isOwner() };
      return null;
    }};
    // Owner login: open https://tudominio.com/?owner
    if(new URLSearchParams(location.search).has("owner")){
      window.addEventListener("DOMContentLoaded",()=>{
        const b=document.createElement("button");
        const label=async()=>{ const c=fauth.currentUser; b.textContent=(c&&!c.isAnonymous)?((await isOwner())?"✓ Dueño conectado – Cerrar sesión":"⚠ "+(c.email||"")+" no es el dueño – Cerrar sesión"):"Entrar como dueño (Google)"; };
        label();
        b.style.cssText="position:fixed;left:50%;transform:translateX(-50%);bottom:90px;z-index:9999;padding:12px 18px;border-radius:999px;border:0;font-weight:800;background:#F6C453;color:#3A2400;box-shadow:0 6px 18px rgba(0,0,0,.4)";
        b.onclick=async()=>{ const c=fauth.currentUser; if(c&&!c.isAnonymous){ await fauth.signOut(); location.href=location.pathname; return; }
          try{ await fauth.signInWithPopup(new firebase.auth.GoogleAuthProvider()); location.reload(); }catch(e){ alert("No se pudo iniciar sesión: "+e.message); } };
        document.body.appendChild(b);
        fauth.onAuthStateChanged(()=>{ ownerCache=null; label(); });
      });
    }
  }catch(e){ console.error("Firebase init error",e); }
})();
