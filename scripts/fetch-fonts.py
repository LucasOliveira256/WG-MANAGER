#!/usr/bin/env python3
"""Baixa Chakra Petch e JetBrains Mono (subset latin, woff2) do Google Fonts para web/fonts/.
Rode uma vez no PC de build, antes do docker buildx. As fontes ficam embutidas no binário (offline)."""
import os, re, sys, urllib.request

CSS_URL = ("https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700"
           "&family=JetBrains+Mono:wght@400;500&display=swap")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web", "fonts")


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def parse(css):
    """Devolve [(familia, peso, url)] apenas do bloco '/* latin */' de cada @font-face."""
    out = []
    for m in re.finditer(r"/\*\s*([\w-]+)\s*\*/\s*@font-face\s*\{(.*?)\}", css, re.S):
        subset, body = m.group(1), m.group(2)
        if subset != "latin":
            continue
        fam = re.search(r"font-family:\s*'([^']+)'", body).group(1)
        wt = re.search(r"font-weight:\s*(\d+)", body).group(1)
        url = re.search(r"url\((https://[^)]+\.woff2)\)", body).group(1)
        out.append((fam, wt, url))
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    faces = parse(get(CSS_URL).decode("utf-8"))
    if not faces:
        sys.exit("Nenhuma fonte encontrada na resposta do Google Fonts.")
    for fam, wt, url in faces:
        name = fam.lower().replace(" ", "-") + "-" + wt + ".woff2"
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(get(url))
        print("ok", name)


if __name__ == "__main__":
    main()
