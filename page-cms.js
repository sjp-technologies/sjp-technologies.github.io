/* Live multi-page CMS renderer: text, SEO, hero media, CTAs and second section. */
(async function(){
 const API="https://sjp-website-api.shahjalalpramanik-bpl.workers.dev";
 const leaf=location.pathname.split("/").pop()||"index.html";
 const slug=leaf.toLowerCase().endsWith(".html")?leaf.slice(0,-5):"index";
 const first=(selectors)=>{for(const selector of selectors){const el=document.querySelector(selector);if(el)return el;}return null;};
 const setText=(selectors,value)=>{const el=first(selectors);if(el&&value)el.textContent=value;return el;};
 try{
  const response=await fetch(API+"/page-cms",{cache:"no-store"});if(!response.ok)return;
  const data=await response.json(),p=(data.pages||{})[slug];if(!p)return;
  if(p.title)document.title=p.title;
  if(p.seoDescription){let meta=document.querySelector('meta[name="description"]');if(!meta){meta=document.createElement("meta");meta.name="description";document.head.appendChild(meta);}meta.content=p.seoDescription;}
  setText(["#heroTitle","main .page-hero h1","main .hero h1","main h1"],p.heroText);
  setText(["#heroSubtitle","main .page-hero p","main .hero p"],p.introText);
  setText(["#featuredTitle","main .section .section-title","main h2"],p.sectionTitle);
  setText(["#featuredDescription","main .section .section-copy","main .section p"],p.sectionText);
  const hero=first(["main .page-hero","main .hero"]);
  if(p.heroImage&&hero){
   let img=hero.querySelector("[data-cms-hero-image]");
   if(!img){img=document.createElement("img");img.dataset.cmsHeroImage="true";img.alt="";img.loading="lazy";img.style.cssText="display:block;width:100%;max-height:360px;object-fit:cover;border-radius:18px;margin:0 auto 18px";hero.insertBefore(img,hero.firstChild);}
   img.src=p.heroImage;
  }
  const heroActions=hero||document.querySelector("main");
  if(heroActions&&(p.primaryButtonText||p.secondaryButtonText)){
   let wrap=heroActions.querySelector("[data-cms-actions]");
   if(!wrap){wrap=document.createElement("div");wrap.dataset.cmsActions="true";wrap.style.cssText="display:flex;gap:12px;flex-wrap:wrap;margin-top:16px";heroActions.appendChild(wrap);}
   wrap.replaceChildren();
   for(const [label,url,kind] of [[p.primaryButtonText,p.primaryButtonUrl,"primary"],[p.secondaryButtonText,p.secondaryButtonUrl,"secondary"]]){
    if(!label)continue;const a=document.createElement("a");a.textContent=label;a.href=url||"#";a.className=kind==="primary"?"btn":"btn secondary";if(/^https:\/\//i.test(a.href)&&new URL(a.href).origin!==location.origin){a.target="_blank";a.rel="noopener noreferrer";}wrap.appendChild(a);
   }
  }
  if(p.section2Title||p.section2Text){
   let section=document.querySelector("[data-cms-section-two]");
   if(!section){section=document.createElement("section");section.dataset.cmsSectionTwo="true";section.className="section";const main=document.querySelector("main")||document.body;main.appendChild(section);}
   section.replaceChildren();
   if(p.section2Title){const h=document.createElement("h2");h.className="section-title";h.textContent=p.section2Title;section.appendChild(h);}
   if(p.section2Text){const para=document.createElement("p");para.className="section-copy";para.textContent=p.section2Text;section.appendChild(para);}
  }
  document.documentElement.dataset.cmsPage=slug;
 }catch(_){}
})();