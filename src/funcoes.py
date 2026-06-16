import re
import requests
import json
import os
from urllib.parse import urlparse
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

#===========================================================================
# DOMÍNIOS DE DOCUMENTAÇÃO A IGNORAR NO CAMPO 'references' DA REGRA
#===========================================================================
# Estas URLs são documentação de SINTAXE/ferramenta, não a FONTE da ameaça.
# Não devem entrar no campo 'references' da regra Sigma gerada.
# ATENÇÃO: não inclua aqui domínios que possam ser a fonte real da ameaça
# (ex.: confluence.atlassian.com pode ser a documentação do log que define a
# ameaça — nesse caso é fonte legítima e deve permanecer).
# Lista editável: ajuste conforme necessário.
DOMINIOS_DOC_IGNORAR = [
    "sigmahq.io",
    "sigmahq.github.io",
]


def filtrar_urls_doc(urls: list) -> list:
    """Remove da lista as URLs que apontam para documentação de sintaxe/ferramenta.

    Args:
        urls: lista de URLs extraídas do prompt.

    Returns:
        A lista sem as URLs cujo domínio está em DOMINIOS_DOC_IGNORAR.
    """
    if not urls:
        return urls
    filtradas = []
    for u in urls:
        dominio = urlparse(u).netloc.lower()
        if any(doc in dominio for doc in DOMINIOS_DOC_IGNORAR):
            continue
        filtradas.append(u)
    return filtradas


#função para encontrar todas as menções de CVE e CWE em qualquer texto:
def extrair_referencias(texto: str):
    cves = set(m.group().upper() for m in re.finditer(r"CVE-\d{4}-\d+", texto, re.IGNORECASE))
    cwes = set(m.group().upper() for m in re.finditer(r"CWE-\d+", texto, re.IGNORECASE))
    return cves, cwes

#função para extrair palavras significativas do caminho de uma URL. usado quando a página fica inacessível:
def extrair_palavras_chave_url(url:str):
    caminho = urlparse(url).path
    texto = re.sub(r"[/\-_\.]+", " ", caminho)
    lixo = {"html", "htm", "php", "asp", "aspx", "vuln", "detail", "www"}
    return [
        p.lower() for p in texto.split()
        if len(p) >= 3 and not p.isdigit() and p.lower() not in lixo
    ]

#---------------------------------------------------------------------------
# PRÉ-PROCESSAMENTO ROBUSTO DE PROMPT (suporte ao Nó 1)
#---------------------------------------------------------------------------
# O agente aceita dois "regimes" de prompt:
#  - ESTRUTURADO: traz cabeçalhos conhecidos (# Threat to detect, # References...);
#  - SOLTO: texto corrido, sem cabeçalhos (ex.: "gere uma regra para este evento: <url>").
# As funções abaixo permitem tratar ambos com a mesma lógica, convergindo para uma
# saída comum (uma descrição da ameaça limpa, pronta para o RAG e o gerador).

# cabeçalhos que indicam um prompt ESTRUTURADO. são divididos em dois grupos:
#  - de CONTEXTO: contêm a descrição da ameaça/ambiente (queremos o conteúdo);
#  - de INSTRUÇÃO: dizem ao agente o que fazer (NÃO são descrição da ameaça; ignorar).
CABECALHOS_CONTEXTO = [
    "threat to detect",
    "target environment",
    "references",
    "authoritative references",
    "context",
    "background",
]
CABECALHOS_INSTRUCAO = [
    "requirements",
    "output",
    "instructions",
    "task",
    "role",
]
TODOS_CABECALHOS = CABECALHOS_CONTEXTO + CABECALHOS_INSTRUCAO

# frases-instrução (stopwords de instrução): ruído para a busca semântica do RAG.
# são instruções para o AGENTE, não descrição da AMEAÇA. removidas antes do RAG.
INSTRUCOES_RUIDO = [
    r"generate\s+(one|a|an)?\s*(valid\s+)?sigma\s+rule",
    r"produce\s+(one|a|an)?\s*(valid\s+)?sigma\s+rule",
    r"create\s+(one|a|an)?\s*(valid\s+)?(detection\s+|sigma\s+)?rule",
    r"you\s+are\s+a\s+senior\s+threat\s+detection\s+engineer",
    r"following\s+the\s+specification\s+at",
    r"return\s+only\s+the\s+yaml",
    r"no\s+markdown\s+fences",
    r"no\s+explanations?",
    r"for\s+this\s+event",
    r"in\s+yaml",
]


def detectar_regime(texto: str) -> str:
    """Decide se o prompt é 'estruturado' (tem cabeçalhos) ou 'solto'.

    Args:
        texto: o prompt completo digitado pelo usuário.

    Returns:
        "estruturado" se houver ao menos um cabeçalho conhecido na forma '# Titulo';
        "solto" caso contrário.
    """
    #procura linhas que começam com '#' seguido de um dos cabeçalhos conhecidos
    for linha in texto.splitlines():
        m = re.match(r"^#+\s*(.+?)\s*$", linha.strip())
        if m:
            titulo = m.group(1).strip().lower()
            if any(titulo.startswith(c) for c in TODOS_CABECALHOS):
                return "estruturado"
    return "solto"


def limpar_instrucoes(texto: str) -> str:
    """Remove frases-instrução (ruído) para não poluir a busca semântica do RAG.

    Args:
        texto: trecho de descrição da ameaça (já sem URLs).

    Returns:
        O mesmo texto com as frases-instrução removidas e espaços normalizados.
    """
    limpo = texto
    for padrao in INSTRUCOES_RUIDO:
        limpo = re.sub(padrao, " ", limpo, flags=re.IGNORECASE)
    #normaliza espaços e pontuação solta deixada pela remoção
    limpo = re.sub(r"[ \t]+", " ", limpo)
    limpo = re.sub(r"\n{3,}", "\n\n", limpo)
    return limpo.strip(" :;-\n\t")


def extrair_secoes_tecnicas(texto: str) -> str:
    """Isola as seções de CONTEXTO de um prompt estruturado, ignorando as de instrução.

    Generaliza a versão antiga: antes só pegava 'threat to detect' e 'target
    environment'; agora pega qualquer seção de contexto (ver CABECALHOS_CONTEXTO) e
    descarta explicitamente as de instrução (# Requirements, # Output, etc.).

    Args:
        texto: o prompt (idealmente já sem URLs).

    Returns:
        As seções de contexto concatenadas; ou o texto original se não houver
        nenhum cabeçalho reconhecível (prompt solto).
    """
    #divide o texto nos cabeçalhos markdown ('# Titulo'); re.split com captura
    #mantém o título junto do conteúdo correspondente.
    partes = re.split(r"^#+\s+", texto, flags=re.MULTILINE)
    trechos_relevantes = []
    for bloco in partes:
        if not bloco.strip():
            continue
        primeira_linha = bloco.split("\n", 1)[0].strip().lower()
        #pega só as seções de contexto; ignora as de instrução
        if any(primeira_linha.startswith(c) for c in CABECALHOS_CONTEXTO):
            trechos_relevantes.append(bloco.strip())
    if trechos_relevantes:
        return "\n\n".join(trechos_relevantes)
    return texto


def avaliar_contexto(texto_limpo: str, urls: list, minimo_chars: int = 30) -> bool:
    """Decide se o prompt tem 'contexto pobre' (pouca/nenhuma descrição textual).

    Caso típico: o usuário só forneceu URLs e uma instrução genérica, sem descrever
    a ameaça em texto. A informação está atrás dos links — o agente precisará
    depender do scraping (Nó 2) e, possivelmente, da expansão por LLM.

    Args:
        texto_limpo: a descrição da ameaça já sem URLs e sem frases-instrução.
        urls: lista de URLs encontradas no prompt.
        minimo_chars: limiar de caracteres úteis abaixo do qual o contexto é pobre.

    Returns:
        True se o contexto for considerado pobre; False caso contrário.
    """
    util = (texto_limpo or "").strip()
    #pobre = sobrou pouquíssimo texto E havia URLs (a info está atrás dos links)
    return len(util) < minimo_chars and len(urls) > 0


#função para consultar a API do MITRE para um CVE:
def consulta_mitre(cve_id:str):
    try:
        r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}", timeout=10)
        if r.status_code == 200:
            descricoes = r.json().get("containers",{}).get("cna",{}).get("descriptions",[])
            if descricoes:
                return descricoes[0].get("value", "")   #retorna a descrição ou None
    except requests.exceptions.RequestException:
        pass
    return None


#função que consulta a API do NVD para um CVE:
def consulta_nvd(cve_id:str):
    try:
        url_api = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r = requests.get(url_api, timeout=10)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities",[])
            if vulns:
                cve_item = vulns[0].get("cve",{})
                descricao = next(
                    (x["value"] for x in cve_item.get("descriptions",[]) if x.get("lang") == "en"),
                    None
                )
                cwes = [
                    d["value"]
                    for w in cve_item.get("weaknesses",[])
                    for d in w.get("description",[])
                    if d.get("lang") == "en"
                ]
                cvss = None
                for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if chave in cve_item.get("metrics",{}) and cve_item["metrics"][chave]:
                        cvss = cve_item["metrics"][chave][0].get("cvssData", {}).get("baseScore")
                        break
                return {"descricao": descricao, "cwes": cwes, "cvss": cvss}
    except requests.exceptions.RequestException:
        pass
    return None

# ---------- MITRE ATT&CK (validação de tags) ----------

# cache local do conjunto de técnicas válidas (carregado uma vez)
_TECNICAS_ATTACK = None

def _caminho_cache_attack():
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "..", "data", "attack_tecnicas.json")


def carregar_tecnicas_attack():
    """
    Carrega o conjunto de IDs de técnicas MITRE ATT&CK válidas.
    Tenta o cache local; se não existir, baixa o STIX oficial uma vez.
    Retorna um set de strings minúsculas no formato 't1190', 't1059.001', etc.
    """
    global _TECNICAS_ATTACK
    if _TECNICAS_ATTACK is not None:
        return _TECNICAS_ATTACK

    cache = _caminho_cache_attack()

    # 1) tenta carregar do cache
    if os.path.exists(cache):
        try:
            with open(cache, "r", encoding="utf-8") as f:
                _TECNICAS_ATTACK = set(json.load(f))
                return _TECNICAS_ATTACK
        except (json.JSONDecodeError, OSError):
            pass  # cache corrompido; rebaixa

    # 2) baixa o STIX oficial (Enterprise ATT&CK)
    url = ("https://raw.githubusercontent.com/mitre/cti/master/"
           "enterprise-attack/enterprise-attack.json")
    tecnicas = set()
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            dados = r.json()
            for obj in dados.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "")
                        if ext_id.startswith("T"):
                            tecnicas.add(ext_id.lower())  # ex: 't1190'
            # salva o cache
            os.makedirs(os.path.dirname(cache), exist_ok=True)
            with open(cache, "w", encoding="utf-8") as f:
                json.dump(sorted(tecnicas), f)
    except requests.exceptions.RequestException:
        pass

    _TECNICAS_ATTACK = tecnicas
    return _TECNICAS_ATTACK


def validar_tags_attack(tags: list):
    """
    Separa as tags Sigma em válidas e inválidas conforme a taxonomia ATT&CK.
    - tags no formato 'attack.tXXXX' são checadas contra a base oficial.
    - tags 'attack.<tatica>' (initial-access, execution...) são aceitas.
    - tags que não começam com 'attack.' são deixadas como estão (não são ATT&CK).
    Retorna (tags_validas, tags_invalidas).
    """
    base_tecnicas = carregar_tecnicas_attack()

    # táticas oficiais do Enterprise ATT&CK (não são técnicas, mas são tags válidas)
    taticas_validas = {
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
    }

    validas, invalidas = [], []
    for tag in tags:
        tag_str = str(tag).strip()
        tl = tag_str.lower()

        if not tl.startswith("attack."):
            validas.append(tag_str)   # não é tag ATT&CK; não validamos aqui
            continue

        sufixo = tl.replace("attack.", "", 1)

        if sufixo.startswith("t"):
            # técnica ou sub-técnica: t1190, t1059.001
            if sufixo in base_tecnicas or sufixo.split(".")[0] in base_tecnicas:
                validas.append(tag_str)
            else:
                invalidas.append(tag_str)
        elif sufixo in taticas_validas:
            validas.append(tag_str)
        else:
            invalidas.append(tag_str)

    return validas, invalidas


# ---------- DuckDuckGo (busca incremental) ----------

def busca_duckduckgo(termo: str, max_resultados: int = 5):
    """
    Busca livre no DuckDuckGo, filtrando domínios que servem regras Sigma.
    Falha graciosamente em qualquer erro.
    """
    DDGS = None
    try:
        from ddgs import DDGS
    except ImportError:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            return None

    # domínios que servem/republicam regras Sigma — evitar contaminação
    DOMINIOS_BLOQUEADOS = (
        ".github.com/sigmahq",
        ".github.com/sigmahq/sigma",
        ".raw.githubusercontent.com/sigmahq",
        ".sigmahq.io/rules",
        ".detection.fyi",
        ".sigma-rules.io",
        ".uncoder.io/catalog",
    )

    try:
        resultados = []
        descartados = 0
        with DDGS() as ddgs:
            # pede mais resultados que o necessário, para compensar os filtrados
            for r in ddgs.text(termo, max_results=max_resultados * 2):
                url_res = r.get("href", "").lower()
                if any(d in url_res for d in DOMINIOS_BLOQUEADOS):
                    descartados += 1
                    continue
                titulo = r.get("title", "")
                corpo = r.get("body", "")
                resultados.append(f"{titulo}: {corpo}")
                if len(resultados) >= max_resultados:
                    break
        if descartados:
            print(f"    (DuckDuckGo: {descartados} resultado(s) de fonte Sigma filtrado(s))")
        if resultados:
            return "\n".join(resultados)
    except Exception as e:
        print(f"    (DuckDuckGo indisponível: {e})")
    return None

def extrair_urls_de_referencias(texto: str):
    """
    Extrai URLs que estão na seção '# References' de um prompt estruturado.
    Se não houver seção References, retorna None (sinaliza para usar o fallback:
    todas as URLs do texto).
    """
    # localiza o bloco da seção References (até a próxima seção '#' ou fim do texto)
    match = re.search(
        r"^#\s*references\s*\n(.*?)(?=^#\s|\Z)",
        texto,
        flags=re.MULTILINE | re.IGNORECASE | re.DOTALL
    )
    if not match:
        return None  # não há seção References; o chamador usa o fallback

    bloco_refs = match.group(1)
    urls = re.findall(r"https?://[^\s]+", bloco_refs)
    urls_limpas = [u.rstrip(r".,;!?)\]}>'\"") for u in urls]
    return urls_limpas

def destilar_ameaca(material_bruto: str) -> str:
    """Resume o material coletado (scraping, web) numa descrição factual da ameaça.

    Usada quando o Nó 1 sinaliza CONTEXTO POBRE: o prompt não descreve a ameaça em
    texto (a info está atrás de links). A LLM lê o material bruto coletado pelo Nó 2
    e DESTILA dele 2-3 frases factuais: qual ameaça, em qual produto/log, quais
    indicadores. Isto NÃO gera regra — apenas concentra o sinal semântico.

    DECORRELAÇÃO: usa um modelo de família distinta do gerador (MODELO_DESTILADOR)
    e temperatura ZERO, para evitar que erros de interpretação do destilador
    sejam silenciosamente confirmados pelo gerador. Se o modelo alternativo
    não estiver instalado, faz fallback graciosamente.

    Trava anti-alucinação: o chamador só deve invocar esta função quando houver
    material suficiente (ver LIMIAR_MATERIA_PRIMA).

    Args:
        material_bruto: o texto coletado pelo Nó 2 (conteúdo de URL, busca web, etc.).

    Returns:
        Descrição destilada da ameaça, ou string vazia em caso de falha.
    """
    #limita o material enviado à LLM (contexto + custo); o início costuma conter o essencial
    material = material_bruto.strip()[:3000]

    prompt = (
        "You are a cybersecurity analyst. Read the raw material below (web page "
        "content, search snippets) and extract ONLY the threat to be detected.\n"
        "Write 2-3 short, factual sentences answering: WHAT threat/technique, in "
        "WHICH product or log source, and WHICH concrete indicators (exception "
        "names, fields, keywords, log levels) appear.\n"
        "Do NOT write a Sigma rule. Do NOT invent details not present in the "
        "material. If the material is insufficient, say exactly 'INSUFFICIENT'.\n\n"
        f"RAW MATERIAL:\n{material}\n\n"
        "THREAT DESCRIPTION:"
    )

    # tenta o modelo destilador dedicado; se não estiver instalado, usa fallback
    modelo_usado = MODELO_DESTILADOR
    temperatura_usada = TEMP_DESTILADOR
    try:
        llm = ChatOllama(model=modelo_usado, temperature=temperatura_usada)
        resposta = llm.invoke([HumanMessage(content=prompt)])
        texto = (resposta.content or "").strip()
    except Exception as e:
        #possíveis causas: modelo não instalado, Ollama fora do ar, OOM
        print(f" -> Destilador '{modelo_usado}' indisponível ({e}).")
        print(f" -> Fallback: usando '{MODELO_DESTILADOR_FALLBACK}' "
              f"com temperatura {TEMP_DESTILADOR_FALLBACK}.")
        try:
            modelo_usado = MODELO_DESTILADOR_FALLBACK
            temperatura_usada = TEMP_DESTILADOR_FALLBACK
            llm = ChatOllama(model=modelo_usado, temperature=temperatura_usada)
            resposta = llm.invoke([HumanMessage(content=prompt)])
            texto = (resposta.content or "").strip()
        except Exception as e2:
            print(f" -> Fallback também falhou: {e2}")
            return ""

    print(f"    (destilação feita com '{modelo_usado}' @ temperature={temperatura_usada})")

    #a LLM pode sinalizar que não havia material útil
    if not texto or "INSUFFICIENT" in texto.upper():
        return ""
    return texto
