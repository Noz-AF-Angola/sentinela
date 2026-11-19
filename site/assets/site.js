// Sentinela - site. Copiar comandos e mostrar campanhas. Sem dependências.
(function () {
  "use strict";

  var APOIO = "https://apoio.nozaf.ao";
  var PROJECTO = "sentinela";

  // Botões "Copiar" ao lado dos comandos.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var code = document.getElementById(btn.getAttribute("data-copy"));
      if (!code || !navigator.clipboard) return;
      navigator.clipboard.writeText(code.textContent.trim()).then(function () {
        btn.textContent = "Copiado";
        setTimeout(function () { btn.textContent = "Copiar"; }, 1800);
      });
    });
  });

  var kz = new Intl.NumberFormat("pt-AO", { maximumFractionDigits: 0 });
  var dia = new Intl.DateTimeFormat("pt-AO", { day: "numeric", month: "long", year: "numeric" });

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function num(v) {
    var n = Number(v);
    return isFinite(n) && n >= 0 ? n : 0;
  }

  // Uma campanha: tudo por textContent, nada vindo da API é interpretado como HTML.
  function campanha(c) {
    var meta = num(c.meta_kz), feito = num(c.angariado_kz);
    var box = el("article", "campaign");
    box.appendChild(el("h3", "", String(c.titulo || "Campanha")));
    if (c.descricao) box.appendChild(el("p", "soft", String(c.descricao)));

    var numbers = el("div", "numbers");
    var a = el("span"); a.appendChild(el("strong", "", kz.format(feito) + " Kz")); a.appendChild(document.createTextNode(" angariados"));
    var b = el("span", "", meta ? "meta de " + kz.format(meta) + " Kz" : "");
    numbers.appendChild(a); numbers.appendChild(b);
    box.appendChild(numbers);

    if (meta) {
      var m = el("meter");
      m.min = 0; m.max = meta; m.value = Math.min(feito, meta); m.optimum = meta;
      m.setAttribute("aria-label", Math.round((Math.min(feito, meta) / meta) * 100) + "% da meta");
      box.appendChild(m);
    }
    if (c.fim) {
      var d = new Date(c.fim);
      if (!isNaN(d)) box.appendChild(el("p", "end", "Termina a " + dia.format(d)));
    }
    var link = el("a", "button", "Apoiar esta campanha");
    var q = "?projecto=" + PROJECTO + (c.id !== undefined ? "&campanha=" + encodeURIComponent(String(c.id)) : "");
    link.href = APOIO + "/" + q;
    box.appendChild(link);
    return box;
  }

  function carregar() {
    var ctl = window.AbortController ? new AbortController() : null;
    if (ctl) setTimeout(function () { ctl.abort(); }, 8000);
    return fetch(APOIO + "/v1/campanhas?projecto=" + PROJECTO, { credentials: "omit", cache: "no-store", signal: ctl ? ctl.signal : undefined })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (lista) { return Array.isArray(lista) ? lista : []; });
  }

  // Página Campanhas: lista completa.
  var alvo = document.getElementById("campanhas");
  if (alvo) {
    var estado = document.getElementById("campanhas-estado");
    carregar().then(function (lista) {
      if (!lista.length) {
        estado.textContent = "Não há campanhas abertas neste momento. Pode apoiar o projecto em geral na página Apoiar.";
        return;
      }
      estado.remove();
      lista.forEach(function (c) { alvo.appendChild(campanha(c)); });
    }).catch(function () {
      estado.textContent = "As campanhas não carregaram. Veja-as directamente em apoio.nozaf.ao.";
    });
  }

  // Início: mostra a primeira campanha aberta, se houver; caso contrário a secção fica escondida.
  var teaser = document.getElementById("campanha-destaque");
  if (teaser) {
    carregar().then(function (lista) {
      if (!lista.length) return;
      teaser.querySelector(".slot").appendChild(campanha(lista[0]));
      teaser.classList.add("on");
    }).catch(function () {});
  }
})();
