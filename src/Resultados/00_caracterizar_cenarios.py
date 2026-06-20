"""
================================================================================
00_caracterizar_cenarios.py  (v2)

Objetivo
--------
Caracterizar os 50 cenários do conjunto `test_cases` segundo três dimensões:
(i) FAMÍLIA de fonte de log (agrupamento de 21 logsources detalhados em 5),
(ii) tática MITRE ATT&CK declarada nas tags (NORMALIZADA para os 14 nomes
     oficiais), e
(iii) nível de severidade (level).

Produz CINCO artefatos:
  - impressão no terminal (com barras visuais e relatório de normalização),
  - 00_tabela_A2_principal.csv         (capítulo 5)
  - 00_tabela_A2_apendice_logsource.csv (apêndice — logsource detalhado)
  - 00_detalhe_por_regra.csv           (auditoria, uma linha por regra)
  - 00_relatorio_normalizacao.txt      (rastreabilidade das tags alteradas)

Decisões metodológicas desta versão (v2)
----------------------------------------
1) Táticas não-oficiais do MITRE ATT&CK (encontradas em algumas regras do
   conjunto test_cases) são normalizadas para a tática oficial correspondente:
       stealth             → defense-evasion
       defense-impairment  → defense-evasion
   Todas as normalizações são registradas em `00_relatorio_normalizacao.txt`
   para inclusão em nota de rodapé na Tabela A.2.

2) Logsource é agrupado em 5 famílias por critério hierárquico que considera
   `product` antes de `category` (ver função `classificar_familia_logsource`).
   A tabela detalhada (21 categorias) é preservada e exportada para o apêndice.

Como o script lida com a estrutura de pastas
--------------------------------------------
A pasta `test_cases` é organizada em subpastas, uma por cenário:

    test_cases/
    ├── 1 nome-da-regra-X/
    │   ├── nome-da-regra-X.yml      ← a regra-gabarito (o que queremos)
    │   ├── prompt1.txt
    │   ├── prompt2.txt
    │   └── prompt3.txt
    ├── 2 nome-da-regra-Y/
    │   └── ...

O script entra em cada subpasta e considera o primeiro `.yml` encontrado como
a regra-gabarito. Se a pasta tiver arquivos `.yml` gerados pelo agente (com
sufixos `_prompt1`, `_prompt2`, `_prompt3`), eles são IGNORADOS — só queremos
caracterizar as regras-gabarito originais do SigmaHQ.

Decisões metodológicas
----------------------
1) Tags MITRE: extraímos APENAS as táticas (palavras), não as técnicas (tXXXX).
   Táticas seguem o padrão `attack.<tatica>`. Técnicas seguem `attack.tXXXX`
   ou `attack.tXXXX.YYY`. Distinguir pela presença do prefixo 't' seguido de
   dígito é seguro.

2) Convenção de contagem de táticas: por padrão, contamos TODAS as táticas
   declaradas em cada regra (uma regra com 2 táticas conta nas duas linhas).
   Isso significa que a soma das percentagens na dimensão "Tática" pode
   ultrapassar 100% — registrar isso em nota de rodapé na monografia.
   Para mudar para "apenas a primeira tática", basta alterar a flag abaixo.

3) Agrupamento em "outras": categorias minoritárias são agrupadas para manter
   a tabela enxuta. A regra é: listar nominalmente o que somar ≥ 80% acumulado
   (em ordem decrescente de frequência), agrupar o resto em "outras".

Dependências
------------
    pyyaml
================================================================================
"""

import csv
import os
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

# =============================================================================
# CONFIGURAÇÕES — AJUSTE OS CAMINHOS CONFORME SEU AMBIENTE
# =============================================================================

# Pasta raiz com os 50 cenários (cada um em sua subpasta)
PASTA_TEST_CASES = Path("/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/test_cases")

# Pasta onde os artefatos de análise serão salvos
PASTA_SAIDA = Path("/home/daniela/Documents/TCC/tcc_sigma_agent/analise")

# Limite acumulado (em %) para listar categorias nominalmente.
# O resto é agrupado em "outras". 80% é o padrão da literatura.
LIMITE_ACUMULADO_PERCENTUAL = 80.0

# Se True, conta TODAS as táticas declaradas em uma regra (soma pode > 100%).
# Se False, conta apenas a PRIMEIRA tática declarada (soma == 100%).
CONTAR_TODAS_TATICAS = True

# Padrão regex para reconhecer técnicas MITRE (ex: attack.t1059, attack.t1059.001)
# Tudo que NÃO casar é tratado como tática (ex: attack.execution)
REGEX_TECNICA_MITRE = re.compile(r"^attack\.t\d+", re.IGNORECASE)

# Padrão regex para identificar uma tática MITRE (começa com 'attack.' e
# tem só letras/hífens depois)
REGEX_TATICA_MITRE = re.compile(r"^attack\.([a-z][a-z\-]*)$", re.IGNORECASE)


# =============================================================================
# NORMALIZAÇÃO DE TÁTICAS MITRE
# =============================================================================
# Algumas regras do conjunto test_cases declaram tags que não correspondem às
# 14 táticas oficiais do MITRE ATT&CK Enterprise. Estas são normalizadas para
# os nomes oficiais para garantir comparabilidade. Toda normalização é
# registrada e exportada em relatório separado.

MAPA_NORMALIZACAO_MITRE = {
    "stealth":             "defense-evasion",
    "defense-impairment":  "defense-evasion",
}

# As 14 táticas oficiais do MITRE ATT&CK Enterprise (referência: MITRE, 2024)
TATICAS_OFICIAIS_MITRE = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
}


def normalizar_tatica(tatica: str) -> tuple[str, bool]:
    """Aplica o mapa de normalização. Retorna (tatica_final, foi_normalizada)."""
    t = tatica.lower().strip()
    if t in MAPA_NORMALIZACAO_MITRE:
        return MAPA_NORMALIZACAO_MITRE[t], True
    return t, False


# =============================================================================
# CLASSIFICAÇÃO EM FAMÍLIAS DE LOGSOURCE
# =============================================================================
# Os 21 valores distintos de logsource_descricao são agregados em 5 famílias
# para a tabela do capítulo 5. A tabela detalhada (21 linhas) vai para o
# apêndice. A regra de classificação é hierárquica: avalia primeiro `product`
# (que identifica plataforma cloud/SaaS sem ambiguidade), depois `category`.

PRODUTOS_CLOUD_SAAS = {
    "azure", "m365", "github", "okta", "bitbucket", "kubernetes",
}
PRODUTOS_REDE = {"zeek", "cisco", "huawei"}
PRODUTOS_LINUX_MAC = {"linux", "macos"}

CATEGORIAS_REDE = {"network_connection", "dns", "proxy"}
CATEGORIAS_APLICACAO = {"application", "database", "antivirus", "webserver"}
CATEGORIAS_ENDPOINT = {
    "process_creation", "file_event", "file_delete", "file_rename",
    "registry_event", "registry_set", "image_load", "pipe_created",
    "create_remote_thread", "process_access",
    "ps_module", "ps_script", "ps_classic_start", "ps_classic_provider_start",
}


def classificar_familia_logsource(category: str, product: str, service: str) -> str:
    """Atribui uma das 5 famílias com base em (category, product, service).

    A ordem das verificações é importante e segue precedência:
        1. Cloud / SaaS (product define inequivocamente)
        2. Rede e proxy (category ou product específicos)
        3. Aplicação (incluindo banco, antivírus e webservers)
        4. Endpoint Linux/macOS (product define)
        5. Endpoint Windows (default para categorias de endpoint Win)
        6. (não classificado) — sinaliza para inspeção manual
    """
    category = (category or "").lower().strip()
    product = (product or "").lower().strip()

    # 1) Cloud / SaaS — precedência alta
    if product in PRODUTOS_CLOUD_SAAS:
        return "Cloud / SaaS"

    # 2) Rede e proxy
    if category in CATEGORIAS_REDE:
        return "Rede e proxy"
    if product in PRODUTOS_REDE:
        return "Rede e proxy"

    # 3) Aplicação
    if category in CATEGORIAS_APLICACAO:
        return "Aplicação"

    # 4) Endpoint Linux/macOS — checado ANTES de Windows porque o product
    # tem precedência sobre a categoria de endpoint
    if product in PRODUTOS_LINUX_MAC:
        return "Endpoint Linux/macOS"

    # 5) Endpoint Windows (default para categorias de endpoint sem product Linux/Mac)
    if category in CATEGORIAS_ENDPOINT or product == "windows":
        return "Endpoint Windows"

    return "(não classificado)"


# =============================================================================
# DESCOBERTA DAS REGRAS-GABARITO
# =============================================================================

def localizar_regras_gabarito(pasta_raiz: Path) -> list[Path]:
    """Percorre as subpastas de test_cases e retorna o caminho do .yml gabarito
    de cada cenário.

    Estratégia: para cada subpasta, considera o primeiro .yml encontrado que
    NÃO tenha sufixo de prompt (`_prompt1`, `_prompt2`, `_prompt3`).
    """
    regras = []
    sufixos_geradas = ("_prompt1", "_prompt2", "_prompt3")

    if not pasta_raiz.is_dir():
        raise FileNotFoundError(f"Pasta não encontrada: {pasta_raiz}")

    for subpasta in sorted(pasta_raiz.iterdir()):
        if not subpasta.is_dir():
            continue
        candidatos = [
            arq for arq in sorted(subpasta.iterdir())
            if arq.suffix.lower() in (".yml", ".yaml")
            and not any(suf in arq.stem for suf in sufixos_geradas)
        ]
        if candidatos:
            regras.append(candidatos[0])
        else:
            print(f"   AVISO: nenhum .yml gabarito em {subpasta.name}")

    return regras


# =============================================================================
# EXTRAÇÃO DOS METADADOS DE UMA REGRA
# =============================================================================

def extrair_metadados(caminho_yml: Path) -> dict:
    """Lê o YAML e devolve um dict com:
        - logsource_category
        - logsource_product
        - logsource_service
        - logsource_descricao    (string para a tabela, ver abaixo)
        - level
        - taticas                (list[str], todas as táticas MITRE distintas)
        - tatica_primaria        (str, primeira tática listada)
        - tem_tag_mitre          (bool)
    Para a coluna logsource_descricao, escolhemos:
        - se houver `category`, usamos `category`
        - senão, se houver `product`, usamos `product` (genérico)
        - senão, "não informado"
    Essa escolha replica a convenção do SigmaHQ.
    """
    with open(caminho_yml, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    logsource = doc.get("logsource", {}) or {}
    category = logsource.get("category")
    product = logsource.get("product")
    service = logsource.get("service")

    if category:
        descricao = category
    elif product:
        descricao = f"{product} (genérico)"
    else:
        descricao = "não informado"

    level = doc.get("level") or "não informado"

    taticas_originais = []   # antes de normalizar
    taticas_normalizadas = []
    normalizacoes = []       # registro de (original → normalizada)
    tags = doc.get("tags") or []
    for tag in tags:
        tag = str(tag).strip()
        if REGEX_TECNICA_MITRE.match(tag):
            continue   # é técnica, pula
        m = REGEX_TATICA_MITRE.match(tag)
        if m:
            tatica_original = m.group(1).lower()
            tatica_norm, foi_norm = normalizar_tatica(tatica_original)
            taticas_originais.append(tatica_original)
            taticas_normalizadas.append(tatica_norm)
            if foi_norm:
                normalizacoes.append((tatica_original, tatica_norm))

    # remove duplicatas preservando ordem
    taticas_originais_unicas = list(dict.fromkeys(taticas_originais))
    taticas_normalizadas_unicas = list(dict.fromkeys(taticas_normalizadas))

    familia = classificar_familia_logsource(category or "", product or "", service or "")

    return {
        "arquivo": caminho_yml.name,
        "logsource_category": category or "",
        "logsource_product": product or "",
        "logsource_service": service or "",
        "logsource_descricao": descricao,
        "logsource_familia": familia,
        "level": level,
        "taticas_originais": taticas_originais_unicas,
        "taticas_normalizadas": taticas_normalizadas_unicas,
        "tatica_primaria": (taticas_normalizadas_unicas[0]
                            if taticas_normalizadas_unicas else "(sem tag MITRE)"),
        "tem_tag_mitre": bool(taticas_normalizadas_unicas),
        "normalizacoes": normalizacoes,   # lista de (original, normalizada)
    }


# =============================================================================
# CONTAGEM E AGRUPAMENTO
# =============================================================================

def agrupar_em_outras(
    contagem: Counter,
    total_para_percentual: int,
    limite_acumulado: float = LIMITE_ACUMULADO_PERCENTUAL,
) -> list[tuple[str, int, float]]:
    """Recebe um Counter com a contagem por categoria e retorna uma lista de
    triplas (categoria, quantidade, percentual), listando nominalmente as
    categorias mais frequentes até cobrir `limite_acumulado` %, e agrupando
    o resto em "outras".

    `total_para_percentual` é o denominador para o cálculo de %. Para
    logsource e level deve ser 50 (número de regras). Para táticas, depende
    da convenção (ver `CONTAR_TODAS_TATICAS`).
    """
    if not contagem:
        return []

    # O threshold de "80% acumulado" deve ser calculado sobre a soma real das
    # contagens, não sobre 100%. Isso importa quando uma observação pode ser
    # contada em várias categorias (multi-rotulação), como nas táticas MITRE.
    soma_total_contagens = sum(contagem.values())
    itens_ordenados = contagem.most_common()
    resultado = []
    acumulado_qtd = 0
    indice_corte = len(itens_ordenados)

    for i, (cat, qtd) in enumerate(itens_ordenados):
        pct_para_exibicao = 100.0 * qtd / total_para_percentual
        pct_acumulado_real = 100.0 * acumulado_qtd / soma_total_contagens
        if pct_acumulado_real >= limite_acumulado and i > 0:
            indice_corte = i
            break
        resultado.append((cat, qtd, pct_para_exibicao))
        acumulado_qtd += qtd

    # agrupa o restante em "outras"
    if indice_corte < len(itens_ordenados):
        qtd_outras = sum(qtd for _, qtd in itens_ordenados[indice_corte:])
        n_categorias_outras = len(itens_ordenados) - indice_corte
        pct_outras = 100.0 * qtd_outras / total_para_percentual
        resultado.append(
            (f"outras ({n_categorias_outras} categorias)", qtd_outras, pct_outras)
        )

    return resultado


# =============================================================================
# IMPRESSÃO E EXPORTAÇÃO
# =============================================================================

def imprimir_distribuicao_terminal(titulo: str, dist: list[tuple[str, int, float]]) -> None:
    """Imprime a distribuição com barras visuais no terminal."""
    print(f"\n{titulo}")
    print("-" * 70)
    if not dist:
        print("  (sem dados)")
        return
    for cat, qtd, pct in dist:
        barra = "█" * qtd
        print(f"  {cat:<30s} {qtd:>3d}   ({pct:5.1f}%)   {barra}")


def montar_linhas_csv_resumo(
    distribuicoes: dict[str, list[tuple[str, int, float]]],
) -> list[dict]:
    """Monta as linhas no formato exato da Tabela A.2:
        Dimensão | Categoria | Quantidade | Percentual
    """
    linhas = []
    for nome_dim, dist in distribuicoes.items():
        for cat, qtd, pct in dist:
            linhas.append({
                "Dimensão": nome_dim,
                "Categoria": cat,
                "Quantidade": qtd,
                "Percentual": f"{pct:.1f}%",
            })
    return linhas


# =============================================================================
# EXECUÇÃO PRINCIPAL
# =============================================================================

def main() -> int:
    PASTA_SAIDA.mkdir(parents=True, exist_ok=True)

    # 1) Localiza as regras-gabarito
    print(f"-> Procurando regras-gabarito em '{PASTA_TEST_CASES}'...")
    try:
        regras = localizar_regras_gabarito(PASTA_TEST_CASES)
    except FileNotFoundError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return 1
    print(f"   Encontradas {len(regras)} regras-gabarito.")
    if len(regras) != 50:
        print(f"   AVISO: o esperado eram 50 regras. Verifique a estrutura de pastas.")

    # 2) Extrai metadados de cada regra
    print("\n-> Extraindo metadados...")
    detalhes = []
    for caminho in regras:
        try:
            meta = extrair_metadados(caminho)
            detalhes.append(meta)
        except yaml.YAMLError as e:
            print(f"   ERRO de parsing em {caminho.name}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"   ERRO inesperado em {caminho.name}: {e}", file=sys.stderr)

    n_regras = len(detalhes)
    print(f"   {n_regras} regras parseadas com sucesso.")

    # 3) Contagens
    cont_familia = Counter(d["logsource_familia"] for d in detalhes)
    cont_logsource_detalhado = Counter(d["logsource_descricao"] for d in detalhes)
    cont_level = Counter(d["level"] for d in detalhes)

    # Táticas: usa táticas NORMALIZADAS
    if CONTAR_TODAS_TATICAS:
        cont_tatica = Counter()
        for d in detalhes:
            if d["taticas_normalizadas"]:
                cont_tatica.update(d["taticas_normalizadas"])
            else:
                cont_tatica["(sem tag MITRE)"] += 1
        denominador_taticas = n_regras
    else:
        cont_tatica = Counter(d["tatica_primaria"] for d in detalhes)
        denominador_taticas = n_regras

    # 4) Agrupa minoritárias em "outras"
    # Família: NÃO agrupa (são só 5 categorias, todas devem aparecer)
    dist_familia = agrupar_em_outras(cont_familia, n_regras, limite_acumulado=100.0)
    dist_logsource_detalhado = agrupar_em_outras(cont_logsource_detalhado, n_regras)
    dist_level = agrupar_em_outras(cont_level, n_regras, limite_acumulado=100.0)
    dist_tatica = agrupar_em_outras(cont_tatica, denominador_taticas)

    # 5) Imprime no terminal
    print("\n" + "=" * 70)
    print(f"CARACTERIZAÇÃO DOS {n_regras} CENÁRIOS DE TESTE")
    print("=" * 70)
    imprimir_distribuicao_terminal(
        "Família de fonte de log (Tabela A.2 — Capítulo 5)", dist_familia)
    imprimir_distribuicao_terminal(
        "Tática MITRE ATT&CK (normalizada)", dist_tatica)
    imprimir_distribuicao_terminal("Severidade (level)", dist_level)
    print()
    imprimir_distribuicao_terminal(
        "Logsource detalhado (Apêndice)", dist_logsource_detalhado)

    # 6) Relatório de normalização — para nota de rodapé da Tabela A.2
    print("\n" + "=" * 70)
    print("RELATÓRIO DE NORMALIZAÇÃO DE TAGS MITRE")
    print("=" * 70)
    regras_normalizadas = [d for d in detalhes if d["normalizacoes"]]
    total_normalizacoes = sum(len(d["normalizacoes"]) for d in detalhes)
    if not regras_normalizadas:
        print("Nenhuma tag precisou ser normalizada.")
    else:
        print(f"{len(regras_normalizadas)} regra(s) tiveram pelo menos uma tag "
              f"normalizada (total de {total_normalizacoes} normalizações).\n")
        for d in regras_normalizadas:
            for orig, norm in d["normalizacoes"]:
                print(f"  - {d['arquivo']:<60s}  {orig} → {norm}")

    # Salva relatório em arquivo
    caminho_relatorio = PASTA_SAIDA / "00_relatorio_normalizacao.txt"
    with open(caminho_relatorio, "w", encoding="utf-8") as f:
        f.write("RELATÓRIO DE NORMALIZAÇÃO DE TAGS MITRE ATT&CK\n")
        f.write("=" * 70 + "\n\n")
        f.write("Mapa de normalização aplicado:\n")
        for orig, norm in MAPA_NORMALIZACAO_MITRE.items():
            f.write(f"  {orig} → {norm}\n")
        f.write("\n")
        if regras_normalizadas:
            f.write(f"{len(regras_normalizadas)} regra(s) tiveram pelo menos uma tag "
                    f"normalizada (total de {total_normalizacoes} normalizações):\n\n")
            for d in regras_normalizadas:
                for orig, norm in d["normalizacoes"]:
                    f.write(f"  {d['arquivo']}: {orig} → {norm}\n")
        else:
            f.write("Nenhuma tag precisou ser normalizada.\n")
    print(f"\n-> Relatório de normalização salvo em: {caminho_relatorio}")

    # 7) Salva CSV-resumo principal (Tabela A.2 do capítulo 5)
    distribuicoes_principal = {
        "Família de fonte de log": dist_familia,
        "Tática MITRE ATT&CK": dist_tatica,
        "Severidade (level)": dist_level,
    }
    linhas_csv = montar_linhas_csv_resumo(distribuicoes_principal)
    caminho_csv_principal = PASTA_SAIDA / "00_tabela_A2_principal.csv"
    with open(caminho_csv_principal, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Dimensão", "Categoria", "Quantidade", "Percentual"]
        )
        writer.writeheader()
        writer.writerows(linhas_csv)
    print(f"-> Tabela A.2 (capítulo 5) salva em: {caminho_csv_principal}")

    # 8) Salva CSV do apêndice (logsource detalhado)
    distribuicoes_apendice = {
        "Logsource (detalhado)": dist_logsource_detalhado,
    }
    linhas_csv_apendice = montar_linhas_csv_resumo(distribuicoes_apendice)
    caminho_csv_apendice = PASTA_SAIDA / "00_tabela_A2_apendice_logsource.csv"
    with open(caminho_csv_apendice, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Dimensão", "Categoria", "Quantidade", "Percentual"]
        )
        writer.writeheader()
        writer.writerows(linhas_csv_apendice)
    print(f"-> Tabela do apêndice salva em:     {caminho_csv_apendice}")

    # 9) Salva CSV-detalhe (uma linha por regra) para auditoria
    caminho_csv_detalhe = PASTA_SAIDA / "00_detalhe_por_regra.csv"
    with open(caminho_csv_detalhe, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "arquivo", "logsource_descricao", "logsource_familia",
            "logsource_category", "logsource_product", "logsource_service",
            "level", "taticas_originais", "taticas_normalizadas",
            "tatica_primaria", "tem_tag_mitre", "houve_normalizacao",
        ])
        writer.writeheader()
        for d in detalhes:
            linha = {
                "arquivo": d["arquivo"],
                "logsource_descricao": d["logsource_descricao"],
                "logsource_familia": d["logsource_familia"],
                "logsource_category": d["logsource_category"],
                "logsource_product": d["logsource_product"],
                "logsource_service": d["logsource_service"],
                "level": d["level"],
                "taticas_originais": ";".join(d["taticas_originais"]),
                "taticas_normalizadas": ";".join(d["taticas_normalizadas"]),
                "tatica_primaria": d["tatica_primaria"],
                "tem_tag_mitre": d["tem_tag_mitre"],
                "houve_normalizacao": bool(d["normalizacoes"]),
            }
            writer.writerow(linha)
    print(f"-> CSV-detalhe salvo em:            {caminho_csv_detalhe}")

    # 10) Avisos finais
    sem_mitre = sum(1 for d in detalhes if not d["tem_tag_mitre"])
    if sem_mitre:
        print(f"\nNOTA: {sem_mitre} regras não declaram tag MITRE ATT&CK.")
        print("      Foram contadas como '(sem tag MITRE)' na dimensão Tática.")

    nao_classificadas = [d for d in detalhes if d["logsource_familia"] == "(não classificado)"]
    if nao_classificadas:
        print(f"\nATENÇÃO: {len(nao_classificadas)} regra(s) não couberam em nenhuma "
              f"das 5 famílias. Inspecione e ajuste classificar_familia_logsource():")
        for d in nao_classificadas:
            print(f"  - {d['arquivo']}  (category={d['logsource_category']}, "
                  f"product={d['logsource_product']})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
