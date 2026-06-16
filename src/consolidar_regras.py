import os
import re

BASE_DIR = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/regras_organizadas_para_avaliar"
OUTPUT_DIR = os.path.join(BASE_DIR, "_consolidados")

EXPECTED_FILES = ["A.yml", "B.yml", "C.yml", "D.yml", "E.yml"]

def encontrar_regra_original(subpasta):
    nomes_candidatos = {"A.yml", "B.yml", "C.yml", "D.yml", "E.yml"}
    for nome in os.listdir(subpasta):
        if nome.endswith(".yml") and nome not in nomes_candidatos:
            return nome
    return None


def ler_arquivo(caminho):
    """Lê o conteúdo de um arquivo com fallback de encoding."""
    for enc in ("utf-8", "latin-1"):
        try:
            with open(caminho, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    return f"[ERRO: não foi possível ler {caminho}]"


def processar_subpasta(subpasta_path, numero_regra, nome_subpasta):
    """Lê todos os arquivos da subpasta e gera o conteúdo consolidado."""
    linhas = []

    # Arquivos A, B, C, D, E
    for letra in EXPECTED_FILES:
        caminho = os.path.join(subpasta_path, letra)
        if os.path.isfile(caminho):
            linhas.append(f"# Arquivo: {letra}")
            linhas.append(ler_arquivo(caminho))
        else:
            linhas.append(f"# Arquivo: {letra}")
            linhas.append(f"[AUSENTE: arquivo '{letra}' não encontrado]")
        linhas.append("---")

    # Regra original (.yml)
    nome_yml = encontrar_regra_original(subpasta_path)
    if nome_yml:
        caminho_yml = os.path.join(subpasta_path, nome_yml)
        linhas.append(f"# Arquivo original: {nome_yml}")
        linhas.append(ler_arquivo(caminho_yml))
    else:
        linhas.append("# Arquivo original: [NÃO ENCONTRADO]")
    linhas.append("---")

    return "\n".join(linhas)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Percorre cada pasta de regra no diretório base
    entradas = sorted(os.listdir(BASE_DIR))

    for entrada in entradas:
        pasta_regra = os.path.join(BASE_DIR, entrada)

        # Ignora se não for diretório ou se for a pasta de saída
        if not os.path.isdir(pasta_regra) or entrada == "_consolidados":
            continue

        # Extrai o número da regra do nome da pasta (ex: "48 velocity_ssti_injection" → 48)
        match = re.match(r"^(\d+)", entrada)
        if not match:
            print(f"[AVISO] Pasta sem número no início, ignorando: '{entrada}'")
            continue

        numero_regra = match.group(1)

        # Percorre as subpastas "1" e "2" dentro da pasta da regra
        subpastas = sorted(os.listdir(pasta_regra))
        for sub in subpastas:
            subpasta_path = os.path.join(pasta_regra, sub)

            if not os.path.isdir(subpasta_path):
                continue

            # O nome do arquivo de saída é "NUMERO - SUB.txt"
            nome_saida = f"{numero_regra} - {sub}.txt"
            caminho_saida = os.path.join(OUTPUT_DIR, nome_saida)

            conteudo = processar_subpasta(subpasta_path, numero_regra, entrada)

            with open(caminho_saida, "w", encoding="utf-8") as f:
                f.write(conteudo)

            print(f"[OK] Gerado: {nome_saida}")

    print(f"\nConcluído! Arquivos salvos em: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()