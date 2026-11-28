/* Live multi-page CMS renderer. Non-empty owner values override the matching page copy. */
(async function(){
  const API="https://sjp-website-api.shahjalalpramanik-bpl.workers.dev";
  const leaf=location.pathname.split("/").pop()||"index.html";
  const slug=leaf.toLowerCase().endsWith(".html")?leaf.slice(0,-5):"index";
  const selectors={
    title:["main h1","h1"],
    heroText:["#heroTitle","main .hero h1","main h1"],
    introText:["#heroSubtitle","main .hero p","main p"],
    sectionTitle:["#featuredTitle","main h2"],
    sectionText:["#featuredDescription","main .section-copy","main h2 + p"]
  };
  const first=(list)=>{for(const s of list){const e=document.querySelector(s);if(e)return e;}return null;};
  try{
    const r=await fetch(API+"/page-cms",{cache:"no-store"});if(!r.ok)return;
    const d=await r.json(),p=(d.pages||{})[slug];if(!p)return;
    if(p.title){document.title=p.title;const e=first(selectors.title);if(e)e.textContent=p.title;}
    for(const key of ["heroText","introText","sectionTitle","sectionText"]){
      const value=String(p[key]||"").trim(),e=first(selectors[key]);if(value&&e)e.textContent=value;
    }
    document.documentElement.dataset.cmsPage=slug;
  }catch(_){}
})();