import os
import yaml
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "..", "data", "test_cases")

# Coleta dos metadados
categorias = []
produtos = []
servicos = []
niveis = []
tags = []
total = 0

for arquivo in os.listdir(TEST_DIR):
    if not arquivo.endswith(".yml"):
        continue
    caminho = os.path.join(TEST_DIR, arquivo)
    with open(caminho, "r", encoding="utf-8") as f:
        try:
            doc = yaml.safe_load(f)
            if not doc:
                continue
            total += 1

            logsource = doc.get("logsource", {})
            categorias.append(logsource.get("category", "não informado"))
            produtos.append(logsource.get("product", "não informado"))
            servicos.append(logsource.get("service", "não informado"))

            niveis.append(doc.get("level", "não informado"))

            for tag in doc.get("tags", []):
                # Pega só o prefixo do tag (ex: "attack.t1059" -> "attack")
                prefixo = tag.split(".")[0] if "." in tag else tag
                tags.append(prefixo)
        except yaml.YAMLError:
            continue

# Relatório
print(f"\n=== Análise de Diversidade — {total} regras de teste ===\n")

def imprime_distribuicao(titulo, lista):
    print(f"\n{titulo} (únicos: {len(set(lista))}):")
    contagem = Counter(lista).most_common()
    for valor, qtd in contagem:
        barra = "█" * qtd
        print(f"  {valor:25s} {barra} {qtd}")

imprime_distribuicao("PRODUTOS", produtos)
imprime_distribuicao("CATEGORIAS", categorias)
imprime_distribuicao("SERVIÇOS", servicos)
imprime_distribuicao("NÍVEIS DE SEVERIDADE", niveis)
imprime_distribuicao("FRAMEWORKS DE TAGS", tags)