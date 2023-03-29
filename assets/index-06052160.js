import{d as V,r as A,c as S,a as t,w as x,v as f,b as r,e as _,E as a,f as h,o as D,p as E,g as z}from"./index-42dbb469.js";const v=16,w=new TextEncoder,K=new TextDecoder,U=1e3,F=w.encode("XHWnDAT6ehMVY2zD");function M(s){const e=[];for(let o=0;o<s.length;o++)e.push(s.charCodeAt(o));return new Uint8Array(e)}async function I(s,e){const o=s.slice(0,v),c=s.slice(v),n=await g(e),l=await crypto.subtle.decrypt({name:"AES-GCM",iv:o},n,c);return K.decode(l)}async function g(s){const e=w.encode(s),o=await crypto.subtle.importKey("raw",e,{name:"PBKDF2"},!1,["deriveKey"]);return await crypto.subtle.deriveKey({name:"PBKDF2",hash:{name:"SHA-256"},iterations:U,salt:F},o,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])}async function G(s,e){const o=await g(e),c=w.encode(s),n=crypto.getRandomValues(new Uint8Array(v)),l=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:n},o,c)),d=new Uint8Array(n.byteLength+l.byteLength);return d.set(n,0),d.set(l,n.byteLength),d}function L(s){let e="";for(let o=0;o<s.length;o++)e+=String.fromCharCode(s[o]);return e}async function R(s,e){const o=M(atob(s));return await I(o,e)}async function j(s,e){const o=await G(s,e);return btoa(L(o))}const i=s=>(E("data-v-93e98185"),s=s(),z(),s),H={class:"text-center"},N=i(()=>t("div",{class:"header"},[t("h1",{class:"title -content"},[t("span",null,"文本加解密工具")])],-1)),P={class:"select -content"},O={class:"select-item"},W=i(()=>t("li",{class:"title-item"},[t("span",null,"加密 / 解密")],-1)),X={class:"reset-item"},Y={class:"main -content"},q={class:"input-box"},J={class:"title-box"},Q=i(()=>t("span",null,"文本",-1)),Z={class:"opt"},$=i(()=>t("i",{class:"iconfont icon-jiami"},null,-1)),ee=i(()=>t("span",null,"加密",-1)),te=i(()=>t("i",{class:"iconfont icon-jiemi"},null,-1)),se=i(()=>t("span",null,"解密",-1)),oe={class:"input-box"},ne={class:"title-box"},ce=i(()=>t("span",null,"密文",-1)),ae=V({__name:"index",setup(s){const e=A({text:"",password:"",ciphertext:""}),o=async()=>{try{e.ciphertext=await j(e.text,e.password),a({message:"加密成功",type:"success"})}catch(y){console.log(y),a.error("加密失败")}},c=async()=>{try{e.text=await R(e.ciphertext,e.password),a({message:"解密成功",type:"success"})}catch(y){console.log(y),a.error("解密失败")}},n=async()=>{await navigator.clipboard.writeText(e.text),a({message:"复制文本成功",type:"success"})},l=async()=>{await navigator.clipboard.writeText(e.ciphertext),a({message:"复制密文成功",type:"success"})},d=()=>{e.text="",a({message:"清空密文成功",type:"success"})},C=()=>{e.ciphertext="",a({message:"清空密文成功",type:"success"})},T=()=>{e.text="",e.password="",e.ciphertext="",a({message:"重置成功",type:"success"})};return(y,p)=>{const m=h("el-input"),B=h("el-form-item"),k=h("el-form"),b=h("el-button");return D(),S("div",H,[N,t("div",P,[t("ul",O,[W,x(t("li",X,[t("i",{class:"iconfont icon-zhongzhi",onClick:T},"重置")],512),[[f,e.text||e.password||e.ciphertext]])])]),t("div",Y,[t("div",q,[t("div",J,[Q,x(t("div",null,[t("i",{class:"iconfont icon-fuzhi",onClick:n},"复制"),t("i",{class:"iconfont icon-empty",onClick:d},"清空")],512),[[f,e.text]])]),r(m,{modelValue:e.text,"onUpdate:modelValue":p[0]||(p[0]=u=>e.text=u),type:"textarea",resize:"none",placeholder:"请输入你要加密的内容"},null,8,["modelValue"])]),t("div",Z,[r(k,null,{default:_(()=>[r(B,{label:""},{default:_(()=>[r(m,{type:"password",modelValue:e.password,"onUpdate:modelValue":p[1]||(p[1]=u=>e.password=u),clearable:"","show-password":"",placeholder:"密匙,可不填"},null,8,["modelValue"])]),_:1})]),_:1}),t("div",null,[r(b,{type:"primary",class:"encryption-btn",onClick:o,disabled:!e.text},{default:_(()=>[$,ee]),_:1},8,["disabled"]),r(b,{type:"success",class:"decryption-btn",onClick:c,disabled:!e.ciphertext},{default:_(()=>[te,se]),_:1},8,["disabled"])])]),t("div",oe,[t("div",ne,[ce,x(t("div",null,[t("i",{class:"iconfont icon-fuzhi",onClick:l},"复制"),t("i",{class:"iconfont icon-empty",onClick:C},"清空")],512),[[f,e.ciphertext]])]),r(m,{modelValue:e.ciphertext,"onUpdate:modelValue":p[2]||(p[2]=u=>e.ciphertext=u),type:"textarea",resize:"none",placeholder:"请输入你要解密的内容"},null,8,["modelValue"])])])])}}});const ie=(s,e)=>{const o=s.__vccOpts||s;for(const[c,n]of e)o[c]=n;return o},le=ie(ae,[["__scopeId","data-v-93e98185"]]);export{le as default};
