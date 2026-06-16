"""
Baixa a especificação oficial do Sigma (rules, modifiers, conditions, log-sources)
e salva em data/sigma_spec.md. Roda uma vez; depois disso o juiz lê do disco.
"""
import os
import requests

URLS = [
    "https://sigmahq.io/docs/basics/rules.html",
    "https://sigmahq.io/docs/basics/modifiers.html",
    "https://sigmahq.io/docs/basics/conditions.html",
    "https://sigmahq.io/docs/basics/log-sources.html",
]

def main():
    base = os.path.dirname(os.path.abspath(__file__))
    destino_dir = os.path.join(base, "..", "data")
    os.makedirs(destino_dir, exist_ok=True)
    destino = os.path.join(destino_dir, "sigma_spec.md")

    partes = []
    for url in URLS:
        print(f"Baixando {url}...")
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            # extração simples: deixamos o HTML cru; o juiz é uma LLM grande e
            # consegue lidar com tags. Se quiser limpar, pode usar BeautifulSoup.
            partes.append(f"\n\n===== FONTE: {url} =====\n\n{r.text}")
        except requests.exceptions.RequestException as e:
            print(f"  FALHOU: {e}")

    if not partes:
        print("Nenhuma fonte foi baixada. Abortando.")
        return

    with open(destino, "w", encoding="utf-8") as f:
        f.write("\n".join(partes))
    print(f"OK. Especificação salva em {destino} ({os.path.getsize(destino)} bytes).")

if __name__ == "__main__":
    main()