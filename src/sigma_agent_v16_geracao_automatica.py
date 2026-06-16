import re
import os
import yaml
import uuid
import json
import requests     #biblioteca pra conversar com a internet (pip3 install requests)
from typing import TypedDict
from langchain_huggingface import HuggingFaceEmbeddings
from sentence_transformers import CrossEncoder
# from langchain_community.vectorstores import Chroma       #deprecated
from langchain_chroma import Chroma
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from bs4 import BeautifulSoup
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_DIR = os.path.join(BASE_DIR, "..", "data", "chroma_db")
EMBEDDINGS_MODEL = HuggingFaceEmbeddings(model_name="BAAI/bge-small-en-v1.5")
RERANKER_MODEL = CrossEncoder("BAAI/bge-reranker-base")
PROMPT_PATH = os.path.join(BASE_DIR, "..", "prompts", "sigma_system_prompt.md")
with open(PROMPT_PATH, "r", encoding="utf-8") as f:
    SIGMA_SYSTEM_PROMPT = f.read()
MODELO_GERADOR = "llama3.1"
TEMP_GERADOR = 0.1
MODELO_DESTILADOR = "qwen2.5:7b"   # família diferente da llama -> menos correlação
TEMP_DESTILADOR = 0.0              # destilação é extração factual, sem criatividade; temperatura zero reduz risco de alucinação
MODELO_DESTILADOR_FALLBACK = MODELO_GERADOR
TEMP_DESTILADOR_FALLBACK = 0.0

# JUIZ (Nó 6 - validação semântica)
MODELO_JUIZ = "qwen2.5:14b"
TEMP_JUIZ = 0.0
USAR_JUIZ = True

ARQUIVO_SPEC_SIGMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "sigma_spec.md"
)
# pasta onde os pareceres do juiz são salvos (um .parecer.txt por regra gerada)
#PASTA_PARECERES = os.path.join(
#    os.path.dirname(os.path.abspath(__file__)), "..", "pareceres"
#)

# >>>>>>>> máquina de estados <<<<<<<<<<
# nó 1 = classificador determinístico de entrada (Entendimento)
# nó 2 = procura informações nas APIs (threat intelligence)  <-- roda ANTES do RAG
# nó 3 = recupera contexto com RAG (usa a descrição da API p/ enriquecer a busca)
# nó 4 = criação da regra com LLM local
# nó 5 = validação com o Sigma CLI
# OBS: a API (nó 2) roda antes do RAG (nó 3) para que a descrição técnica da ameaça
#      (ex.: a descrição do CVE vinda do MITRE/NVD) sirva de consulta semântica rica
#      ao banco vetorial, recuperando exemplos mais relevantes.

from funcoes import (
    extrair_referencias,
    extrair_palavras_chave_url,
    extrair_secoes_tecnicas,
    extrair_urls_de_referencias,
    detectar_regime,
    limpar_instrucoes,
    avaliar_contexto,
    filtrar_urls_doc,
    consulta_mitre,
    consulta_nvd,
    validar_tags_attack,
    busca_duckduckgo,
)

# >>>>>>>> ESTADO <<<<<<<<<     (caderno de anotações)
class GraphState(TypedDict):
    input_usuario: str       #entrada: "gere uma regra para ..."
    tipo_input: str          #pode ser cve, uma hash ou 'texto_livre'
    termo_busca: str         #cve ou hash extraído
    url_fornecida: list       #possível url que esteja no input
    texto_para_rag: str        #descrição da ameaça pré-processada (nó 1)
    contexto_pobre: bool       #flag: input só com URLs/sem descrição textual da ameaça
    contexto_rag: str        #exemplos de regras recuperados (nó 3)
    contexto_api: str        #dados técnicos da ameaça (nó 2)
    regra_gerada: str        #YAML gerado pela LLM (nó 4)
    erro_validacao: str      #erro do sigma-cli
    tentativas: int          #qtas vezes a LLM tentou refazer a regra
    parecer_juiz: str          # JSON com o veredito completo do juiz

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 1 (classificador determinístico de entrada) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# Pré-processador ROBUSTO: lida tanto com prompts ESTRUTURADOS (com cabeçalhos
# '# Threat to detect', '# References'...) quanto com prompts SOLTOS (texto corrido).
# Decide o regime uma vez e processa de acordo, convergindo para uma saída comum:
#   - tipo_input  : cve / hash / texto_livre
#   - termo_busca : o CVE/hash isolado (se houver)
#   - url_fornecida: URLs da ameaça (sem as de documentação de sintaxe)
#   - texto_para_rag: descrição da ameaça, limpa de URLs e de frases-instrução
#   - contexto_pobre: True se sobrou pouca descrição (info está atrás dos links)
def no_1_classificador(state: GraphState) -> GraphState:

    print("\n[Nó 1] Classificando input...")
    texto = state.get("input_usuario", "")

    # (a) detecta o regime do prompt
    regime = detectar_regime(texto)
    print(f" -> Regime detectado: {regime}")

    # (b) extrai URLs conforme o regime
    if regime == "estruturado":
        #tenta a seção '# References'; se não houver, pega todas as URLs do texto
        urls_das_refs = extrair_urls_de_referencias(texto)
        if urls_das_refs is not None:
            urls_brutas = urls_das_refs
            print(" -> URLs extraídas da seção '# References'.")
        else:
            urls_brutas = re.findall(r"https?://[^\s]+", texto)
            urls_brutas = [u.rstrip(r".,;!?)\]}>'\"") for u in urls_brutas]
            print(" -> Estruturado sem '# References'; usando todas as URLs.")
    else:
        #regime solto: pega todas as URLs do texto
        urls_brutas = re.findall(r"https?://[^\s]+", texto)
        urls_brutas = [u.rstrip(r".,;!?)\]}>'\"") for u in urls_brutas]
        print(" -> Prompt solto; coletando todas as URLs do texto.")

    # (c) filtra URLs de documentação de sintaxe (ex.: sigmahq.io) — não são a ameaça
    urls_limpas = filtrar_urls_doc(urls_brutas)
    if len(urls_limpas) < len(urls_brutas):
        print(f" -> {len(urls_brutas) - len(urls_limpas)} URL(s) de documentação ignorada(s).")

    # (d) remove TODAS as URLs do texto antes de procurar CVE/hash e montar a descrição
    texto_sem_url = texto
    for u in urls_brutas:   #remove até as de doc, para não sujar a descrição
        texto_sem_url = texto_sem_url.replace(u, "")

    # (e) identifica CVE ou hash isolado
    padrao_cve = re.search(r"CVE-\d{4}-\d+", texto_sem_url, re.IGNORECASE)
    padrao_hash = re.search(r"\b[a-fA-F0-9]{32,64}\b", texto_sem_url)

    if padrao_cve:
        tipo = "cve"
        termo = padrao_cve.group().upper()
    elif padrao_hash:
        tipo = "hash"
        termo = padrao_hash.group().lower()
    else:
        tipo = "texto_livre"
        termo = ""

    # (f) monta a descrição da ameaça para o RAG, conforme o regime
    if regime == "estruturado":
        #isola as seções de contexto (ignora # Requirements, # Output, etc.)
        descricao = extrair_secoes_tecnicas(texto_sem_url)
    else:
        #solto: o texto inteiro (sem URLs) é a descrição
        descricao = texto_sem_url

    # (g) limpa frases-instrução (ruído para a busca semântica)
    texto_para_rag = limpar_instrucoes(descricao)

    # (h) avalia se o contexto é pobre (pouca descrição + só URLs)
    contexto_pobre = avaliar_contexto(texto_para_rag, urls_limpas)

    #-- logs de diagnóstico --
    print(f" -> Tipo: {tipo}")
    if termo:
        print(f" -> Termo isolado: {termo}")
    if urls_limpas:
        print(f" -> URLs da ameaça: {len(urls_limpas)} encontrada(s).")
        for u in urls_limpas:
            print(f"    - {u}")
    print(f" -> Descrição p/ RAG: {len(texto_para_rag)} caractere(s).")
    if contexto_pobre:
        print(" -> !! CONTEXTO POBRE: descrição insuficiente; info está atrás dos links.")
        print("    (a expansão por LLM no Nó 2 tentará destilar a ameaça do scraping)")

    return {
        "tipo_input": tipo,
        "termo_busca": termo,
        "url_fornecida": urls_limpas,
        "texto_para_rag": texto_para_rag,
        "contexto_pobre": contexto_pobre,
    }

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#>>>>>>>>>>>>>>>>>>>> NÓ 2 (API) <<<<<<<<<<<<<<<<<<<<<<<<
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#--- limiar mínimo de material bruto p/ a expansão (destilação) rodar ---
#abaixo disso, não há matéria-prima suficiente: destilar "do nada" levaria a LLM a
#ALUCINAR uma ameaça plausível porém falsa. Então a expansão é pulada.
LIMIAR_MATERIA_PRIMA = 200

def destilar_ameaca(material_bruto: str) -> str:
    """Resume o material coletado (scraping, web) numa descrição factual da ameaça.

    Usada quando o Nó 1 sinaliza CONTEXTO POBRE: o prompt não descreve a ameaça em
    texto (a info está atrás de links). A LLM lê o material bruto coletado pelo Nó 2
    e DESTILA dele 2-3 frases factuais: qual ameaça, em qual produto/log, quais
    indicadores. Isto NÃO gera regra — apenas concentra o sinal semântico.

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

    try:
        llm = ChatOllama(model=MODELO_GERADOR, temperature=TEMP_GERADOR)
        resposta = llm.invoke([HumanMessage(content=prompt)])
        texto = (resposta.content or "").strip()
    except Exception as e:
        print(f" -> Expansão falhou (LLM indisponível): {e}")
        return ""

    #a LLM pode sinalizar que não havia material útil
    if not texto or "INSUFFICIENT" in texto.upper():
        return ""
    return texto


#Vai buscar informações técnicas na internet sobre a ameaça extraída.
#Roda ANTES do RAG para que a descrição da ameaça enriqueça a busca vetorial.
#Se a API falhar ou não tiver internet, o agente não dá erro, vai seguir em frente.
def no_2_api(state: GraphState) -> GraphState:

    print("\n[Nó 2] Buscando dados em APIs externas...")
    
    tipo = state.get("tipo_input", "")  #usar .get() evita q o programa quebre (keyerror) caso as chaves não existam no estado
    termo = state.get("termo_busca", "")
    urls = state.get("url_fornecida", [])
    entrada_usuario = state.get("input_usuario", "")
    contexto_api = "Nenhum dado externo coletado."      #inicialização da váriavel que vai pegar esse contexto
    trechos = []

    if isinstance(urls, str):       #se por acaso vier string, normaliza pra lista
        urls = [urls] if urls else []

    #procura CVEs e CWEs em todo o texto de entrada do usuário:
    cves_encontrados, cwes_encontrados = extrair_referencias(entrada_usuario)

    #procura uma URL para acessar:
    if urls:
        print(f" -> {len(urls)} fornecida(s) para processar.")
        
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }

        for i, url in enumerate(urls, start=1):

            #Conversão de URL do github para a versão raw
            if "github.com" in url and "/blob/" in url:
                url_raw = url.replace("github.com", "raw.githubusercontent.com")
                url_raw = url_raw.replace("/blob/", "/")
                print(f" -> URL do github convertida para raw: {url_raw}")
                url = url_raw

            acesso_ok = False
            try:
                resposta_url = requests.get(url, timeout=10, headers=headers)
                if resposta_url.status_code == 200:
                    soup = BeautifulSoup(resposta_url.text, "html.parser")
                    # pega parágrafos, artigos, cabeçalhos, tabelas e listas.
                    # cabeçalhos (h1-h3) e tabelas (td/th) são onde docs de log
                    # costumam expor os NOMES REAIS dos campos de auditoria — conteúdo
                    # crítico para gerar a regra (ex.: campos do Bitbucket audit log).
                    elementos = soup.find_all(
                        ["p", "article", "h1", "h2", "h3", "td", "th", "li"]
                    )
                    texto_limpo = " ".join(
                        e.get_text(separator=" ", strip=True) for e in elementos
                    )
                    if not texto_limpo:   # fallback se a página não usa tags semânticas
                        texto_limpo = soup.get_text(separator=" ", strip=True)
                    trechos.append(f"Conteúdo da URL {url}:\n{texto_limpo[:1500]}")
                    print(" -> Conteúdo da URL extraído com sucesso.")
                    acesso_ok = True
                else:
                    print(f" -> ERRO HTTP {resposta_url.status_code} ao acessar a URL.")
            except requests.exceptions.RequestException as e:
                print(f" -> Falha ao acessar a URL: {e}")
            
            #mesmo se o acesso funcionar, vai procurar CVE/CWE na URL:
            cves_url, cwes_url = extrair_referencias(url)
            cves_encontrados.update(cves_url)
            cwes_encontrados.update(cwes_url)

            #se a URL falhar, extrai as palavras-chave do caminho (fallback):
            if not acesso_ok:
                palavras = extrair_palavras_chave_url(url)
                if palavras:
                    trechos.append(
                        f"\tURL inacessível. Palavras extraídas da URL: {', '.join(palavras)}"
                    )
                    print(f" -> Palavras da URL: {', '.join(palavras)}")
        
    #Consulta o MITRE e o NVD para cada CVE encontrado no texto ou na URL:
    if cves_encontrados:
        for cve_id in sorted(cves_encontrados):
            print(f" -> Consultando MITRE e NVD para {cve_id}...")

            desc_mitre = consulta_mitre(cve_id)
            if desc_mitre:
                trechos.append(f"MITRE - {cve_id}:\n{desc_mitre}")
                print(" -> Dados obtidos do MITRE.")
            else:
                print(" -> Sem dados obtidos do MITRE.")
            
            dados_nvd = consulta_nvd(cve_id)
            if dados_nvd:
                texto = f"NVD - {cve_id}:\n"
                if dados_nvd["descricao"]:
                    texto += f"Descrição: {dados_nvd['descricao']}\n"
                if dados_nvd["cwes"]:
                    texto += f"CWE associado: {', '.join(dados_nvd['cwes'])}\n"
                    cwes_encontrados.update(dados_nvd["cwes"])
                if dados_nvd["cvss"]:
                    texto += f"CVSS: {dados_nvd['cvss']}\n"
                trechos.append(texto)
                print(" -> Dados obtidos do NVD.")
            else:
                print(" -> Dados não obtidos do NVD.")

    #Registra os CWEs encontrados como contexto adicional:
    if cwes_encontrados:
        trechos.append(f"CWEs identificados: {', '.join(sorted(cwes_encontrados))}")

    #Se for Hash consulta a API do VirusTotal:
    if tipo == "hash" and termo:
        #print(f" -> Consultando plataforma para a hash '{termo}'. . .")
        #as hashes são consultadas no virustotal.com, mas ele exige uma API key pessoal. tenho aqui uma simulação apenas para entender a lógica
        trechos.append(
            f"Simulação de API: a hash {termo} foi identificada como malware\n"
            f"{termo} cria processo x em diretórios temporários.\n"
            f"{termo} está associada à man in the middle."
        )
        print(" -> Dados da hash carregados.")

    # ~* BUSCA DUCKDUCKGO (incremento sempre, após as APIs) *~
    # Escolhe o melhor termo disponível para a busca livre:
    termo_busca_web = termo if termo else state.get("texto_para_rag", "")
    if termo_busca_web:
        # limita o tamanho da query (DuckDuckGo não lida bem com textos longos)
        termo_busca_web = termo_busca_web[:200]
        print(f" -> Busca complementar no DuckDuckGo: {termo_busca_web[:60]}...")
        resultado_web = busca_duckduckgo(termo_busca_web, max_resultados=5)
        if resultado_web:
            trechos.append(f"Resultados da busca web (DuckDuckGo):\n{resultado_web}")
            print(" -> Resultados da web obtidos.")
        else:
            print(" -> Sem resultados da web (ou lib indisponível).")
    
    #6: junta tudo
    if trechos:
        contexto_api = "\n\n---\n\n".join(trechos)
    else:
        print(" -> Sem fonte de texto com referências.")

    #7: EXPANSÃO (destilação) — só quando o Nó 1 sinalizou CONTEXTO POBRE.
    #   o prompt não descrevia a ameaça; tentamos destilá-la do material coletado.
    if state.get("contexto_pobre"):
        material = contexto_api if contexto_api != "Nenhum dado externo coletado." else ""
        if len(material.strip()) >= LIMIAR_MATERIA_PRIMA:
            print("\n -> Contexto pobre + material suficiente: destilando ameaça com a LLM...")
            descricao_destilada = destilar_ameaca(material)
            if descricao_destilada:
                print(" -> Ameaça destilada com sucesso.")
                print(f"    {descricao_destilada[:160]}...")
                #SOMA COM PRIORIDADE: destilação no topo, material bruto preservado abaixo
                contexto_api = (
                    f"DESCRIÇÃO DESTILADA DA AMEAÇA (gerada a partir das fontes):\n"
                    f"{descricao_destilada}\n\n---\n\n{contexto_api}"
                )
            else:
                print(" -> Destilação não produziu descrição útil (material insuficiente).")
        else:
            print("\n -> Contexto pobre, mas material insuficiente p/ destilar; seguindo sem expansão.")

    return {"contexto_api": contexto_api}   #atualiza o graphstate com a matéria-prima técnica

# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>> NÓ 3 (procura contexto no RAG) <<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# i)primeiro crio o banco (chromadb) para transformar as regras em vetores matemáticos (embeddings) e os salvar no chromadb;
# ii) depois o agente lê o banco e busca no RAG as regras mais parecidas com a entrada;
# uso o modelo bge-small-en-v1.5 de embeddings.
# então:    o nó 3 acessa o chromadb e busca as regras Sigma mais parecidas com a entrada;
#           essas regras servirão de molde pra LLM (few-shot prompting).
# NOVIDADE: como o nó 2 (API) já rodou, a descrição técnica da ameaça (ex.: descrição
#           do CVE vinda do MITRE/NVD) já está em contexto_api. Quando ela existe, vira
#           o sinal semântico mais forte para a busca vetorial, recuperando exemplos
#           muito mais relevantes do que o código opaco de um CVE/hash.

#limite de caracteres da parte da API que entra na consulta vetorial.
#motivo: o bge-small-en-v1.5 perde qualidade perto do limite de tokens; manter a
#consulta focada (~800 chars) recupera exemplos mais precisos do que jogar 5000 chars.
LIMITE_API_NA_CONSULTA = 800

def _extrair_descricao_relevante_api(contexto_api: str, limite: int = LIMITE_API_NA_CONSULTA) -> str:
    """Seleciona a parte mais útil do contexto_api para usar como consulta ao RAG.

    Prioriza as descrições técnicas estruturadas (MITRE, NVD, CWE) sobre o conteúdo
    bruto de URL, porque elas concentram o sinal semântico da ameaça. Trunca o
    resultado em `limite` caracteres para não diluir o embedding.

    Args:
        contexto_api: o texto completo reunido pelo nó 2 (API).
        limite: número máximo de caracteres a retornar.

    Returns:
        Trecho priorizado e truncado, ou string vazia se não houver descrição útil.
    """
    if not contexto_api or contexto_api.strip() == "Nenhum dado externo coletado.":
        return ""

    #os trechos no contexto_api são separados por "\n\n---\n\n" (ver nó 2)
    blocos = contexto_api.split("\n\n---\n\n")

    #prefixos que indicam descrição técnica de alto valor semântico
    #(a descrição destilada pela expansão tem prioridade máxima)
    prefixos_ricos = ("DESCRIÇÃO DESTILADA", "MITRE", "NVD", "CWEs", "Simulação de API")
    blocos_ricos = [b for b in blocos if b.strip().startswith(prefixos_ricos)]

    #se achou descrições estruturadas, usa-as; senão, cai pro conteúdo geral (URLs/web)
    fonte = "\n\n".join(blocos_ricos) if blocos_ricos else contexto_api
    return fonte.strip()[:limite]


def no_3_rag(state: GraphState) -> GraphState:

    print("\n[Nó 3] Buscando contexto no RAG - com re-ranking\n")

    #-- monta a consulta ao banco vetorial seguindo uma prioridade clara --
    #1) se a API trouxe descrição rica, ENRIQUECE: input do usuário + descrição da API;
    #2) senão, usa o texto pré-processado (seções técnicas) do nó 1;
    #3) senão, usa o termo isolado (CVE/hash) cru;
    #4) senão, usa o input completo (fallback).

    desc_api = _extrair_descricao_relevante_api(state.get("contexto_api", ""))

    if desc_api:
        #base = o melhor sinal vindo do usuário (termo isolado ou seções técnicas)
        base_usuario = state.get("termo_busca") or state.get("texto_para_rag") \
                       or state.get("input_usuario", "")
        termo_pesquisa = f"{base_usuario}\n\n{desc_api}".strip()
        origem = "input + descrição da API (enriquecido)"
    elif state.get("texto_para_rag"):
        termo_pesquisa = state["texto_para_rag"]
        origem = "seções técnicas"
    elif state.get("termo_busca"):
        termo_pesquisa = state["termo_busca"]
        origem = "termo isolado (CVE/hash)"
    else:
        termo_pesquisa = state.get("input_usuario", "")
        origem = "fallback (input completo)"

    #gancho da flag: se o nó 1 marcou contexto pobre, apenas registra (a expansão por
    #LLM, quando implementada no nó 2, já terá enriquecido contexto_api antes daqui).
    if state.get("contexto_pobre"):
        print(" -> Aviso: nó 1 sinalizou CONTEXTO POBRE para este input.")

    print(f" -> Estratégia: {origem}")
    print(f" -> ChromaDB recebe ({len(termo_pesquisa)} caracteres): "
          f"{termo_pesquisa[:120]}...\n")

    # Carregamos o banco vetorial persistido
    vector_store = Chroma(
        persist_directory=CHROMA_DIR,
        embedding_function=EMBEDDINGS_MODEL
    )

    # 1a busca no RAG usando similaridade de cosseno; busca ampla, 20 candidatos:
    candidatos = vector_store.similarity_search(termo_pesquisa, k=20)

    if not candidatos:
        print(" -> Aviso: nenhuma regra similar encontrada no banco.")
        return {"contexto_rag": "Nenhuma exemplo recuperado."}
    print(f" -> {len(candidatos)} regras candidatas recuperadas do ChromaDB.")

    # re-ranking - cross-encoder avalia cada par (pergunta + candidato)
    pares = [(termo_pesquisa, doc.page_content) for doc in candidatos]
    scores = RERANKER_MODEL.predict(pares)

    # ordena do maior score p menor e pega os 5 melhores:
    candidatos_com_score = sorted(zip(scores, candidatos), key=lambda x: x[0], reverse=True)
    top_5 = candidatos_com_score[:5]

    print(f" -> re-ranking concluído.")
    print(f" -> scores: {[round(float(s),3) for s, _ in top_5]}")

    # ~* DUMP DO TOP-1 *~
    print("\n -> [DUMP TOP-1] primeiros 400 chars do exemplo #1:")
    top1_score, top1_doc = top_5[0]
    print("-" * 60)
    print(top1_doc.page_content[:400])
    print("-" * 60)
    if hasattr(top1_doc, "metadata") and top1_doc.metadata:
        print(f" -> origem (metadata): {top1_doc.metadata}")

    # ~* DIAGNÓSTICO DE COERÊNCIA DO RAG *~
    # Extrai title + logsource (category/product/service) de cada top-5 para
    # verificar se os exemplos recuperados são coerentes entre si. Se vierem
    # categorias misturadas (proxy + process_creation + dns, p.ex.), a LLM
    # pode acabar fundindo campos de exemplos incompatíveis na regra final.
    print("\n -> [DIAGNÓSTICO RAG] coerência de logsource dos top-5 exemplos:")
    categorias_vistas = []
    produtos_vistos = []
    for i, (score, doc) in enumerate(top_5, start=1):
        # tenta parsear o YAML do exemplo; se falhar, segue sem quebrar
        try:
            regra_dict = yaml.safe_load(doc.page_content)
        except yaml.YAMLError:
            regra_dict = None

        if isinstance(regra_dict, dict):
            titulo = regra_dict.get("title", "(sem título)")
            logsrc = regra_dict.get("logsource", {}) or {}
            categoria = logsrc.get("category", "—")
            produto = logsrc.get("product", "—")
            servico = logsrc.get("service", "—")
            categorias_vistas.append(categoria)
            produtos_vistos.append(produto)
            print(f"    EX {i} (score {float(score):.3f}): {titulo[:55]}")
            print(f"           logsource: category={categoria} | "
                  f"product={produto} | service={servico}")
        else:
            print(f"    EX {i} (score {float(score):.3f}): "
                  f"(não foi possível parsear o YAML do exemplo)")

    # Resumo da heterogeneidade: quantas categorias/produtos DISTINTOS apareceram?
    cats_unicas = set(c for c in categorias_vistas if c and c != "—")
    prods_unicos = set(p for p in produtos_vistos if p and p != "—")
    print(f" -> Categorias distintas nos top-5: {len(cats_unicas)} "
          f"({', '.join(sorted(cats_unicas)) if cats_unicas else 'nenhuma'})")
    print(f" -> Produtos distintos nos top-5:   {len(prods_unicos)} "
          f"({', '.join(sorted(prods_unicos)) if prods_unicos else 'nenhum'})")
    if len(cats_unicas) >= 3:
        print(" -> ATENÇÃO: alta heterogeneidade de category nos exemplos do RAG. "
              "A LLM pode misturar campos de logsources incompatíveis.")

    contexto_formatado = "\n\n".join([
        f"### EXEMPLO {i} ###\n{doc.page_content}"
        for i, (_, doc) in enumerate(top_5, start=1)
    ])
    return {"contexto_rag": contexto_formatado}


# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>>>> NÓ 4 (GERAÇÃO DA REGRA - LLM) <<<<<<<<<<<<
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 
def no_4_gerador(state: GraphState) -> GraphState:
    tentativa_atual = state.get("tentativas", 0) + 1    #sinalizar quantas tentativas
    print(f"\n[Nó 4] Gerando a regra... Tentativa {tentativa_atual}")

    #llm = ChatOllama(model="qwen2.5:1.5b", temperature=0.1)
    llm = ChatOllama(model="llama3.1", temperature=0.1)

# ~* Lista explícita de URLs permitidas para 'references:' ~*
    urls_permitidas = state.get("url_fornecida", [])
    if urls_permitidas:
        bloco_urls = "USER-PROVIDED REFERENCES (use EXACTLY these URLs in 'references:', no others):\n"
        bloco_urls += "\n".join(f"- {u}" for u in urls_permitidas)
    else:
        bloco_urls = (
            "USER-PROVIDED REFERENCES: None.\n"
            "Either omit the 'references:' field entirely OR set it to an empty list. "
            "Do NOT fabricate URLs."
        )

    #USER PROMPT:
    user_prompt = f"""USER REQUEST:
{state['input_usuario']}

{bloco_urls}

FORMATTING TEMPLATE - base the YAML structure on these real Sigma rules: 
{state['contexto_rag']}

ADDITIONAL TECHNICAL CONTEXT - use to build detection logic if relevant:
{state['contexto_api']}

REASONING STEP (mandatory):
Before writing the YAML, think briefly inside a <thinking>...</thinking> block
about the following four points. Be concise (1-2 sentences each):
  (a) LOGSOURCE: which category fits best (proxy, process_creation, 
      network_connection, dns, webserver, file_event, registry_event, 
      firewall...)? Justify based on where the indicator would appear.
  (b) FIELDS: which specific log fields contain the indicator of the threat?
  (c) MODIFIERS: for each field, is |contains, |endswith, |startswith, or 
      exact match the correct choice? Remember: use |contains for path 
      fragments that may appear anywhere; |endswith only for file extensions 
      or terminal tokens.
  (d) ATT&CK: which technique (tXXXX) best describes this threat? Avoid 
      defaulting to phishing (t1566) for non-phishing threats.

OUTPUT REQUIREMENTS:
1. First, output the <thinking>...</thinking> block with your reasoning.
2. Immediately after, output the YAML rule with NO markdown fences and NO 
   further explanations.
3. If the USER REQUEST contains URLs, put them in 'references:'.
4. Do NOT copy URLs from the FORMATTING TEMPLATE.
5. Do NOT invent URLs.
"""
    
    # caso hajam novas tentativas:
    erro_anterior = state.get("erro_validacao", "")
    if erro_anterior and erro_anterior != "APROVADO":
        user_prompt += f"""

ATTENTION - the previous attempt failed validation with this error:
{erro_anterior}

Fix this specific problem and return a corrected, valid Sigma rule."""

    mensagens = [
        SystemMessage(content=SIGMA_SYSTEM_PROMPT),
        HumanMessage(content=user_prompt)
    ]

    print(" -> Enviando contexto para a GPU")
    resposta = llm.invoke(mensagens)   #chama a LLM
    print(" -> Regra gerada.")
    return{"regra_gerada": resposta.content}
    
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# >>>>>>>>> NÓ 5 (VALIDADOR SINTÁTICO) <<<<<<<<<< 
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#vê se o YAML gerado pela LLM possui algum erro; confere a qualidade.
def no_5_validador(state: GraphState) ->GraphState:

    print("\n[Nó 5] Revisando em 3 etapas a qualidade da regra gerada...")

    regra_revisao = state.get("regra_gerada", "")
    tentativas = state.get("tentativas", 0) + 1

    # ~* LIMPEZA DE MARKDOWN *~ agora vai limpar tudo de markdown e/ou vai extrair tudo entre ``` e ```:
    marcador = "`" * 3
    padrao_regex = marcador + r"[^\n]*\n(.*?)\n?" + marcador
    match = re.search(padrao_regex, regra_revisao, re.DOTALL | re.IGNORECASE)
    if match:
        yaml_limpo = match.group(1).strip() #if match else regra_revisao.strip()
    else:
        yaml_limpo = regra_revisao.strip()  #remove crases manualmente caso o regex falhe
        if yaml_limpo.startswith(marcador):     #remove a linha inicial se começar com ```
            linhas = yaml_limpo.split("\n",1) 
            yaml_limpo = linhas[1] if len(linhas) > 1 else ""
        if yaml_limpo.rstrip().endswith(marcador):
            yaml_limpo = yaml_limpo.rstrip()[:-len(marcador)].rstrip()

    # ~* REMOÇÃO DO BLOCO DE RACIOCÍNIO (chain-of-thought) *~
    # O Nó 4 instrui a LLM a raciocinar dentro de <thinking>...</thinking>
    # antes de escrever a regra. Aqui descartamos esse bloco, mantendo apenas
    # o YAML. Se a LLM omitir o bloco (não é catastrófico), seguimos normalmente.
    match_think = re.search(
        r"<thinking>.*?</thinking>",
        yaml_limpo,
        flags=re.DOTALL | re.IGNORECASE
    )
    if match_think:
        raciocinio = match_think.group(0)
        print(f" -> [Raciocínio da LLM capturado: {len(raciocinio)} chars]")
        # descomente a linha abaixo se quiser inspecionar o raciocínio em cada execução
        # print(raciocinio)
        yaml_limpo = re.sub(
            r"<thinking>.*?</thinking>\s*",
            "",
            yaml_limpo,
            flags=re.DOTALL | re.IGNORECASE
        ).strip()

    #se o agente gerou várias regras separadas por '---', extrai só a primeira.
    if "\n---" in yaml_limpo or yaml_limpo.startswith("---"):
        print(" -> Detectado múltiplos documentos YAML; mantendo apenas o primeiro.")
        try:
            documentos = list(yaml.safe_load_all(yaml_limpo))
            documentos_validos = [d for d in documentos if isinstance(d, dict) and d]
            if documentos_validos:
                yaml_limpo = yaml.safe_dump(
                    documentos_validos[0],
                    sort_keys=False,
                    allow_unicode=True,
                    default_flow_style=False
                )
            else:
                msg_erro = "Nenhum documento YAML válido encontrado entre os múltiplos gerados."
                print(f"    ERRO: \n{msg_erro}")
                return {"erro_validacao": msg_erro, "tentativas": tentativas}
        except yaml.YAMLError as e:
            msg_erro = f"Falha ao separar documentos YAML múltiplos. Detalhes: {e}"
            print(f"    ERRO: \n{msg_erro}")
            return {"erro_validacao": msg_erro, "tentativas": tentativas}

    # ~* Correção automática de UUID *~ pro caso do agente gerar um id errado
    regra_corrigida = re.sub(
        r'^id:\s*.+$',
        f'id: {uuid.uuid4()}',
        yaml_limpo,
        flags=re.MULTILINE
    )
    if not re.search(r'^id:', regra_corrigida, re.MULTILINE):
        regra_corrigida = re.sub(
            r'^(title:.+)$',
            r'\1\nid: ' + str(uuid.uuid4()),
            regra_corrigida,
            flags=re.MULTILINE
        )
    yaml_limpo = regra_corrigida

    # 1. PyYAML - validação da sintaxe:
    print(" [1/3] -> Validando a sintaxe com PyYAML")
    try:
        regra_dict = yaml.safe_load(yaml_limpo)
    except yaml.YAMLError as e:
        msg_erro = f"[1/3] falhou (erro de sintaxe YAML. \nDetalhes: {e})"
        print(f"    ERRO: \n{msg_erro}")
        return{"erro_validacao":msg_erro, "tentativas":tentativas}
    
    # 2. Validação pelo Python:
    print(" [2/3] -> Validando estrutura mínima")
    if not isinstance(regra_dict, dict):
        msg_erro = "Etapa 2 falhou - o texto gerado não é um YAML válido."
        print(f"    ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    
    campos_obrigatorios = ["title", "logsource", "detection"]
    for campo in campos_obrigatorios:
        if campo not in regra_dict:
            msg_erro = f"Etapa 2 falhou - faltou campo obrigatório: '{campo}'"
            print(f"    ERRO: \n{msg_erro}")
            return {"erro_validacao":msg_erro, "tentativas":tentativas}
        
    # ~* VALIDAÇÃO DE TAGS MITRE ATT&CK *~
    tags = regra_dict.get("tags", [])
    if tags:
        validas, invalidas = validar_tags_attack(tags)
        if invalidas:
            msg_erro = (
                f"Etapa 2 falhou - as seguintes tags não existem na taxonomia "
                f"MITRE ATT&CK: {', '.join(invalidas)}. "
                f"Use APENAS tags no formato 'attack.tXXXX' (técnicas reais, ex: "
                f"attack.t1190) ou 'attack.<tatica>' (ex: attack.initial-access, "
                f"attack.execution, attack.persistence). "
                f"Remova ou substitua as tags inválidas por equivalentes reais."
            )
            print(f"    ERRO: \n{msg_erro}")
            return {"erro_validacao": msg_erro, "tentativas": tentativas}
        else:
            print("    -> Todas as tags ATT&CK são válidas.")

    # 3. pySigma - validação semântica do Sigma:
    print(" [3/3] -> Validação semântica e lógica pelo pySigma")
    try:
        colecao = SigmaCollection.from_yaml(yaml_limpo)
    except SigmaError as e:
        msg_erro = f"Etapa 3 falhou - erro de semântica - \npySigma relata: {e}"
        print(f"    ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    except Exception as e:
        msg_erro = f"Etapa 3 falhou - \npySigma relata: {e}"
        print(f"    ERRO: \n{msg_erro}")
        return {"erro_validacao":msg_erro, "tentativas":tentativas}
    
    print("\n ---> Regra validada pelas 3 etapas.\n")
    return{
        "erro_validacao": "APROVADO",
        "regra_gerada": yaml_limpo,
        "tentativas": tentativas
    }


def no_6_juiz(state: GraphState) -> dict:
    """Nó 6 - juiz semântico (modo ANOTAÇÃO).

    Avalia a regra (já sintaticamente válida pelo Nó 5) contra a especificação
    oficial do Sigma. NÃO bloqueia, NÃO dispara refeed — apenas emite um parecer
    e o salva em um arquivo .parecer.txt paralelo à regra.

    Propósito metodológico: medir quantas regras o Nó 5 aprovou mas que, sob
    análise semântica, apresentam problemas (filtros inventados, modificadores
    errados, MITRE incorreto). Esse delta é evidência empírica para o TCC.
    """
    print("\n=== Nó 6: juiz semântico (modo anotação - qwen2.5:14b) ===")

    if not USAR_JUIZ:
        print(" -> juiz desativado por flag (USAR_JUIZ=False). Pulando.")
        return {"parecer_juiz": ""}

    # carrega a especificação oficial do Sigma do disco
    try:
        with open(ARQUIVO_SPEC_SIGMA, "r", encoding="utf-8") as f:
            spec_sigma = f.read()
    except FileNotFoundError:
        print(f" -> ERRO: {ARQUIVO_SPEC_SIGMA} não encontrado.")
        print(" -> Rode 'python3 baixar_sigma_spec.py' antes de usar o juiz.")
        return {"parecer_juiz": ""}

    # limita o tamanho enviado à LLM (qwen2.5:14b tem contexto amplo, mas a
    # spec em HTML pode ser ~100KB; corte conservador acelera a inferência)
    spec_sigma = spec_sigma[:60000]

    regra_gerada = state.get("regra_gerada", "")
    if not regra_gerada:
        print(" -> sem regra para julgar.")
        return {"parecer_juiz": ""}

    system_prompt = (
        "You are a senior detection engineer auditing Sigma rules. "
        "You have access to the official Sigma specification and must judge "
        "whether the proposed rule follows it correctly for the given threat. "
        "Be critical, factual, and concise. Respond ONLY in valid JSON."
    )

    user_prompt = f"""OFFICIAL SIGMA SPECIFICATION (excerpt from sigmahq.io):
{spec_sigma}

ORIGINAL THREAT DESCRIPTION (what the rule should detect):
{state['input_usuario']}

RULE TO AUDIT:
{regra_gerada}

Evaluate the rule against the specification. For EACH dimension below, classify
as PASS / WARN / FAIL and justify in 1-2 sentences:

1. logsource: does it use category/product/service correctly per the spec? 
   Are the chosen values valid?
2. modifiers: are |contains, |endswith, |startswith used appropriately per 
   the spec (e.g., |contains for path fragments, |endswith for terminal tokens)?
3. condition: is the boolean logic syntactically valid and semantically right?
4. structure: are all required fields present per the spec?
5. semantic_alignment: does the detection logic actually catch the stated 
   threat? (Beyond the spec — essential for usefulness.)
6. invented_filters: did the rule add filters (specific hosts, paths) that 
   have NO basis in the threat description?

Final verdict:
  - "APPROVED" if all dimensions PASS;
  - "APPROVED_WITH_WARNINGS" if any WARN but no FAIL;
  - "REJECTED" if any FAIL.

Respond in this EXACT JSON format (no markdown fences, no extra text):
{{
  "veredito": "APPROVED" | "APPROVED_WITH_WARNINGS" | "REJECTED",
  "dimensoes": {{
    "logsource": {{"status": "PASS|WARN|FAIL", "justificativa": "..."}},
    "modifiers": {{"status": "PASS|WARN|FAIL", "justificativa": "..."}},
    "condition": {{"status": "PASS|WARN|FAIL", "justificativa": "..."}},
    "structure": {{"status": "PASS|WARN|FAIL", "justificativa": "..."}},
    "semantic_alignment": {{"status": "PASS|WARN|FAIL", "justificativa": "..."}},
    "invented_filters": {{"status": "PASS|WARN|FAIL", "justificativa": "..."}}
  }},
  "observacoes_gerais": "comentário breve sobre a qualidade global da regra"
}}"""

    try:
        llm = ChatOllama(model=MODELO_JUIZ, temperature=TEMP_JUIZ)
        resposta = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ])
        texto_resposta = (resposta.content or "").strip()
    except Exception as e:
        print(f" -> juiz indisponível ({e}). Seguindo sem parecer.")
        return {"parecer_juiz": ""}

    # remove eventuais cercas markdown (a llm às vezes embrulha em ```json```)
    texto_resposta = re.sub(r"^```(?:json)?\s*", "", texto_resposta)
    texto_resposta = re.sub(r"\s*```$", "", texto_resposta)

    # tenta parsear o JSON para validar formato
    parecer_dict = None
    try:
        parecer_dict = json.loads(texto_resposta)
    except json.JSONDecodeError as e:
        print(f" -> AVISO: JSON do juiz mal-formado ({e}). Salvando texto cru.")
        # ainda salvamos o que veio, para inspeção manual

    # log compacto no terminal
    if parecer_dict:
        veredito = parecer_dict.get("veredito", "?")
        print(f" -> veredito do juiz: {veredito}")
        for nome, info in parecer_dict.get("dimensoes", {}).items():
            status = info.get("status", "?")
            just = info.get("justificativa", "")[:90]
            print(f"    [{status:4}] {nome}: {just}")

    # formata o parecer para gravação em arquivo
    parecer_formatado = (
        json.dumps(parecer_dict, ensure_ascii=False, indent=2)
        if parecer_dict
        else texto_resposta
    )

    return {"parecer_juiz": parecer_formatado}

# >>>>>>>>>>>>> montagem e compilação do grafo <<<<<<<<<<<<<<
#print("\n")
def criar_agente():
    builder = StateGraph(GraphState)    #montando a arquitetura do grafo langgraph

    # i) adicionando os nós no grafo:
    builder.add_node("entendimento", no_1_classificador)
    builder.add_node("api", no_2_api)
    builder.add_node("rag", no_3_rag)
    builder.add_node("geracao", no_4_gerador)
    builder.add_node("validacao", no_5_validador)
    builder.add_node("juiz", no_6_juiz)              

    # ii) fluxo do grafo:
    #     a API (nó 2) roda antes do RAG (nó 3) para enriquecer a busca vetorial
    #     com a descrição técnica da ameaça.
    builder.add_edge(START, "entendimento")
    builder.add_edge("entendimento", "api")
    builder.add_edge("api", "rag")
    builder.add_edge("rag", "geracao")
    builder.add_edge("geracao", "validacao")

    # iii) rota condicional: após validar, ou refeed (se erro) ou juiz (se ok)
    builder.add_conditional_edges(
        "validacao",    #a decisão parte deste nó
        roteador_de_validacao,      #a função que toma a decisão
        {
            "fim": "juiz",     
            "refazer":"geracao"     #se retornar "refazer", manda de novo pro nó 4
        }
    )
    # iv) aresta terminal do juiz (modo anotação - não bloqueia)
    builder.add_edge("juiz", END)

    # v) compilação:
    agente_sigma = builder.compile()
    return agente_sigma



# >>>>>>>>>>>>> roteador de validação <<<<<<<<<<<<<<
#não altera o estado, apenas lê o erro e decide o próximo passo, se precisa corrigir ou não
def roteador_de_validacao(state: GraphState) -> str:
    erro = state.get("erro_validacao", "")
    tentativas = state.get("tentativas", 0)

    if erro == "APROVADO":
        return "fim"
    if tentativas >= 4:
        print("\n!!! Atingiu 4 tentativas de correção; já é suficiente.")
        return "fim"
    print("\n -> Enviando regra para correção...")
    return "refazer"

# ==========================================
# EXECUÇÃO DO AGENTE
# ==========================================
# =============================================================================
# EXECUÇÃO EM LOTE (BATCH) — geração automática das regras para o TCC
# -----------------------------------------------------------------------------
# Percorre a pasta test_cases. Cada subpasta é UM cenário e segue o padrão:
#       <numero> <nome_original_da_regra>/
#           ├── <regra_original>.yml        (referência / padrão-ouro)
#           ├── prompt1.txt                 (prompt genérico)
#           └── prompt2.txt                 (prompt detalhado)
#
# Para cada cenário, roda o agente com cada prompt encontrado e salva:
#   - a regra gerada      -> <cenario>/<nome_original>_prompt1.yml  (e _prompt2)
#   - o parecer do juiz   -> <cenario>/<nome_original>_prompt1.parecer.txt
# E ao final escreve um CSV com os metadados na raiz de test_cases.
#
# Não há mais leitura interativa do terminal.
# =============================================================================
import csv
import time
import traceback

# >>>>> AJUSTE AQUI o caminho da pasta raiz com os cenários <<<<<
PASTA_TEST_CASES = "/home/daniela/Documents/TCC/tcc_sigma_agent/data_final/test_cases"

# Quais prompts rodar em cada cenário. O script só roda os que existirem na pasta.
PROMPTS_ALVO = ["prompt1", "prompt2", "prompt3"]

# Nomes de arquivo que são a REFERÊNCIA (padrão-ouro), nunca tratados como prompt.
# Qualquer .yml/.yaml dentro da pasta é considerado a regra original.
EXTENSOES_REGRA = (".yml", ".yaml")


def _achar_regra_original(pasta_cenario):
    """Retorna o caminho do .yml de referência (o primeiro encontrado)."""
    for nome in sorted(os.listdir(pasta_cenario)):
        # ignora as regras que o próprio agente já tenha gerado em execuções anteriores
        if any(p in nome for p in PROMPTS_ALVO):
            continue
        if nome.lower().endswith(EXTENSOES_REGRA):
            return os.path.join(pasta_cenario, nome)
    return None


def _nome_base_referencia(caminho_regra_original, fallback):
    """Nome-base usado para nomear as saídas, derivado da regra original."""
    if caminho_regra_original:
        return os.path.splitext(os.path.basename(caminho_regra_original))[0]
    return fallback


def _ler_prompt(pasta_cenario, nome_prompt):
    """Lê promptN.txt da pasta do cenário. Retorna o texto ou None se não existir."""
    caminho = os.path.join(pasta_cenario, nome_prompt + ".txt")
    if os.path.isfile(caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            return f.read()
    return None


def _estado_inicial(texto_prompt):
    return {
        "input_usuario": texto_prompt,
        "tipo_input": "",
        "termo_busca": "",
        "url_fornecida": "",
        "texto_para_rag": "",
        "contexto_pobre": False,
        "contexto_rag": "",
        "contexto_api": "",
        "regra_gerada": "",
        "erro_validacao": "",
        "tentativas": 0,
        "parecer_juiz": "",
    }


if __name__ == '__main__':
    print("\n=== Agente_Sigma — modo BATCH (geração para o TCC) ===")
    print("Carregando modelos...\n")
    agente_sigma = criar_agente()

    if not os.path.isdir(PASTA_TEST_CASES):
        print(f"ERRO: pasta de cenários não encontrada:\n  {PASTA_TEST_CASES}")
        exit(1)

    # lista as subpastas (cada uma é um cenário), em ordem
    cenarios = sorted(
        d for d in os.listdir(PASTA_TEST_CASES)
        if os.path.isdir(os.path.join(PASTA_TEST_CASES, d))
    )
    print(f"Encontrados {len(cenarios)} cenários em test_cases.\n")

    linhas_csv = []   # acumula os metadados de cada (cenário, prompt)

    for idx, nome_cenario in enumerate(cenarios, start=1):
        pasta_cenario = os.path.join(PASTA_TEST_CASES, nome_cenario)
        regra_original = _achar_regra_original(pasta_cenario)
        nome_base = _nome_base_referencia(regra_original, nome_cenario)

        # cenario_id estável = nome da subpasta (numero + nome original)
        cenario_id = nome_cenario

        print("=" * 70)
        print(f"[{idx}/{len(cenarios)}] Cenário: {cenario_id}")
        print(f"  Regra de referência: {os.path.basename(regra_original) if regra_original else '(não encontrada)'}")

        for nome_prompt in PROMPTS_ALVO:
            texto_prompt = _ler_prompt(pasta_cenario, nome_prompt)
            if texto_prompt is None:
                continue  # esse prompt não existe neste cenário; pula

            print(f"\n  -> Rodando {nome_prompt}...")
            t0 = time.time()
            status = "ERRO_EXECUCAO"
            tentativas = 0
            usou_web_search = False
            tipo_input = ""
            contexto_pobre = False
            erro_final = ""
            regra = ""
            parecer = ""

            try:
                resultado = agente_sigma.invoke(_estado_inicial(texto_prompt))

                erro_final = resultado.get("erro_validacao", "")
                tentativas = resultado.get("tentativas", 0)
                tipo_input = resultado.get("tipo_input", "")
                contexto_pobre = resultado.get("contexto_pobre", False)
                usou_web_search = bool(resultado.get("contexto_api", "").strip())
                regra = resultado.get("regra_gerada", "") or ""
                parecer = resultado.get("parecer_juiz", "") or ""

                if erro_final == "APROVADO":
                    status = "APROVADO"
                else:
                    status = "REPROVADO"   # gerou mas não passou na validação
            except Exception as e:
                status = "ERRO_EXECUCAO"
                erro_final = f"{type(e).__name__}: {e}"
                print(f"     !!! Exceção: {erro_final}")
                traceback.print_exc()

            tempo_total = round(time.time() - t0, 2)

            # ---- salva a regra gerada na própria pasta do cenário ----
            caminho_regra_saida = ""
            if regra.strip():
                nome_saida = f"{nome_base}_{nome_prompt}.yml"
                caminho_regra_saida = os.path.join(pasta_cenario, nome_saida)
                with open(caminho_regra_saida, "w", encoding="utf-8") as f:
                    f.write(regra)
                print(f"     regra salva: {nome_saida}")

            # ---- salva o parecer do juiz na própria pasta do cenário ----
            caminho_parecer_saida = ""
            if parecer.strip():
                nome_parecer = f"{nome_base}_{nome_prompt}.parecer.txt"
                caminho_parecer_saida = os.path.join(pasta_cenario, nome_parecer)
                with open(caminho_parecer_saida, "w", encoding="utf-8") as f:
                    f.write("=" * 70 + "\n")
                    f.write("PARECER DO JUIZ SEMÂNTICO (Nó 6)\n")
                    f.write(f"Modelo: {MODELO_JUIZ} (temperatura: {TEMP_JUIZ})\n")
                    f.write(f"Cenário: {cenario_id}\n")
                    f.write(f"Prompt: {nome_prompt}\n")
                    f.write("=" * 70 + "\n\n")
                    f.write(parecer)
                print(f"     parecer salvo: {nome_parecer}")

            # ---- acumula metadados ----
            linhas_csv.append({
                "cenario_id": cenario_id,
                "prompt_usado": nome_prompt,
                "status": status,
                "tentativas": tentativas,
                "tempo_total_s": tempo_total,
                "usou_web_search": usou_web_search,
                "tipo_input": tipo_input,
                "contexto_pobre": contexto_pobre,
                "erro_validacao_final": erro_final,
                "regra_referencia": os.path.basename(regra_original) if regra_original else "",
                "arquivo_regra_gerada": os.path.basename(caminho_regra_saida) if caminho_regra_saida else "",
                "arquivo_parecer": os.path.basename(caminho_parecer_saida) if caminho_parecer_saida else "",
            })

            print(f"     status={status} | tentativas={tentativas} | tempo={tempo_total}s")

    # ---- grava o CSV de metadados na raiz de test_cases ----
    caminho_csv = os.path.join(PASTA_TEST_CASES, "metadados_geracao.csv")
    campos = [
        "cenario_id", "prompt_usado", "status", "tentativas", "tempo_total_s",
        "usou_web_search", "tipo_input", "contexto_pobre",
        "erro_validacao_final", "regra_referencia",
        "arquivo_regra_gerada", "arquivo_parecer",
    ]
    with open(caminho_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=campos)
        writer.writeheader()
        writer.writerows(linhas_csv)

    # ---- resumo final no terminal ----
    total = len(linhas_csv)
    aprovados = sum(1 for r in linhas_csv if r["status"] == "APROVADO")
    print("\n" + "=" * 70)
    print("FIM DA EXECUÇÃO EM LOTE")
    print(f"  Regras geradas (linhas no CSV): {total}")
    print(f"  Aprovadas na validação: {aprovados}/{total}")
    print(f"  Metadados salvos em: {caminho_csv}")
    print("=" * 70 + "\n")
