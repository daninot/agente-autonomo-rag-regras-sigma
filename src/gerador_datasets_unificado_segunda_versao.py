import os
import random
import shutil
import yaml
from collections import Counter

# ============================================================
# CONFIGURAÇÕES
# ============================================================
SIGMA_REPO_DIR  = "/home/daniela/Documents/TCC/sigma/"
TRAIN_DIR       = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/rag_knowledge/"
TEST_DIR        = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/test_cases/"
EXTRA_TEST_DIR  = "/home/daniela/Documents/TCC/tcc_sigma_agent/data/extra_test_cases/"

TRAIN_PERCENTAGE  = 0.75
NEW_TEST_COUNT    = 0
EXTRA_TEST_COUNT  = 10

DIRETORIOS_PERMITIDOS = [
    'rules',
    'rules-compliance',
    'rules-emerging-threats',
    'rules-placeholder',
    'rules-threat-hunting'
]

random.seed(42)


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def get_logsource_key(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            docs = list(yaml.safe_load_all(f))
            for doc in docs:
                if doc and 'logsource' in doc:
                    logsource = doc['logsource']
                    category = logsource.get('category', 'any')
                    product  = logsource.get('product',  'any')
                    service  = logsource.get('service',  'any')
                    return f"{category}_{product}_{service}"
    except Exception:
        pass
    return "unknown"


def get_rule_id(filepath):
    """Extrai o campo 'id' (UUID único) de uma regra Sigma."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            docs = list(yaml.safe_load_all(f))
            for doc in docs:
                if doc and 'id' in doc:
                    return str(doc['id']).strip().lower()
    except Exception:
        pass
    return None


def get_safe_filename(rule_path):
    caminho_relativo = os.path.relpath(rule_path, SIGMA_REPO_DIR)
    return caminho_relativo.replace(os.sep, '_')


def copy_files_to_dir(file_list, dest_dir):
    count = 0
    for src_path in file_list:
        safe_name = get_safe_filename(src_path)
        dst_path  = os.path.join(dest_dir, safe_name)
        shutil.copy2(src_path, dst_path)
        count += 1
    return count


def selecionar_round_robin(regras_por_categoria, quantidade):
    """Seleciona 'quantidade' regras distribuindo uniformemente entre categorias.

    Importante:
    - Embaralha a ordem das categorias UMA VEZ no início (com a seed global,
      portanto reprodutível). Sem isso, as categorias inseridas primeiro no
      dicionário recebiam injustamente mais regras.
    - A cada rodada, pega 1 regra (aleatória) de cada categoria que ainda
      tem itens. Repete até atingir 'quantidade' ou esgotar tudo.
    """
    selecionadas = []
    lista_categorias = [cat for cat in regras_por_categoria if regras_por_categoria[cat]]
    random.shuffle(lista_categorias)    # tira o viés de ordem do dicionário

    while len(selecionadas) < quantidade and lista_categorias:
        for cat in list(lista_categorias):
            if len(selecionadas) >= quantidade:
                break
            if regras_por_categoria[cat]:
                escolhida = random.choice(regras_por_categoria[cat])
                selecionadas.append(escolhida)
                regras_por_categoria[cat].remove(escolhida)
            if not regras_por_categoria[cat]:
                lista_categorias.remove(cat)

    return selecionadas


def relatorio_distribuicao(nome_dataset, lista_regras, top_n=10):
    """Imprime a distribuição de categorias (logsource) de um dataset.
    Útil para auditar visualmente se há viés."""
    print(f"\n--- Distribuição de '{nome_dataset}' ({len(lista_regras)} regras) ---")
    if not lista_regras:
        print("   (vazio)")
        return

    categorias = Counter(get_logsource_key(r) for r in lista_regras)
    total_cats = len(categorias)
    print(f"   Categorias distintas representadas: {total_cats}")

    # Mostra as top_n mais frequentes
    print(f"   Top {min(top_n, total_cats)} categorias mais frequentes:")
    for cat, count in categorias.most_common(top_n):
        pct = (count / len(lista_regras)) * 100
        barra = '█' * int(pct / 2)    # cada bloco = 2%
        print(f"     {count:>5}  ({pct:5.1f}%)  {barra} {cat}")


# ============================================================
# FLUXO PRINCIPAL
# ============================================================

def main():

    # ----------------------------------------------------------
    # PASSO 1 — Varrer o repositório Sigma
    # ----------------------------------------------------------
    print("=" * 60)
    print("PASSO 1: Lendo o repositório Sigma...")
    print("=" * 60)

    all_valid_rules = []
    for root, dirs, files in os.walk(SIGMA_REPO_DIR):
        if root == SIGMA_REPO_DIR:
            dirs[:] = [d for d in dirs if d in DIRETORIOS_PERMITIDOS]
            continue
        for file in files:
            if file.endswith('.yml'):
                all_valid_rules.append(os.path.join(root, file))

    total_repo = len(all_valid_rules)
    print(f" -> {total_repo} regras válidas encontradas no repositório.")

    if total_repo == 0:
        print("ERRO: nenhuma regra encontrada. Verifique SIGMA_REPO_DIR.")
        return

    # ----------------------------------------------------------
    # PASSO 2 — Normalizar nomes dos arquivos em test_cases
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("PASSO 2: Normalizando nomes dos arquivos em test_cases...")
    print("=" * 60)

    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR, exist_ok=True)
        print(f" -> Pasta test_cases não existia; criada vazia.")

    print(" -> Construindo mapa de IDs do repositório...")
    id_para_path_repo = {}
    for rule_path in all_valid_rules:
        rule_id = get_rule_id(rule_path)
        if rule_id:
            id_para_path_repo[rule_id] = rule_path
    print(f" -> {len(id_para_path_repo)} regras com UUID mapeadas.")

    renomeados      = 0
    ja_corretos     = 0
    nao_encontrados = 0

    for filename in [f for f in os.listdir(TEST_DIR) if f.endswith('.yml')]:
        current_path = os.path.join(TEST_DIR, filename)
        rule_id = get_rule_id(current_path)

        if not rule_id or rule_id not in id_para_path_repo:
            nao_encontrados += 1
            continue

        canonical_name = get_safe_filename(id_para_path_repo[rule_id])

        if filename == canonical_name:
            ja_corretos += 1
        else:
            new_path = os.path.join(TEST_DIR, canonical_name)
            os.rename(current_path, new_path)
            renomeados += 1
            print(f"   [{renomeados}] {filename}")
            print(f"        → {canonical_name}")

    print(f" -> Já corretos: {ja_corretos} | Renomeados: {renomeados} | Não encontrados: {nao_encontrados}")

    # ----------------------------------------------------------
    # PASSO 3 — Mapear test_cases → caminhos originais
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("PASSO 3: Mapeando test_cases → repositório...")
    print("=" * 60)

    nomes_em_test = set(f for f in os.listdir(TEST_DIR) if f.endswith('.yml'))

    test_original_paths = set()
    for rule_path in all_valid_rules:
        if get_safe_filename(rule_path) in nomes_em_test:
            test_original_paths.add(rule_path)

    print(f" -> {len(nomes_em_test)} arquivos em test_cases.")
    print(f" -> {len(test_original_paths)} localizados no repositório atual.")
    nao_mapeadas = len(nomes_em_test) - len(test_original_paths)
    if nao_mapeadas > 0:
        print(f"   AVISO: {nao_mapeadas} arquivo(s) não encontrado(s) no repositório.")

    # ----------------------------------------------------------
    # PASSO 4 — Construir pool disponível e agrupar por categoria
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("PASSO 4: Construindo pool disponível...")
    print("=" * 60)

    available_pool = [r for r in all_valid_rules if r not in test_original_paths]
    total_disponivel = len(available_pool)
    print(f" -> {total_disponivel} regras disponíveis")
    print(f"    ({total_repo} total − {len(test_original_paths)} já no test_cases)")

    regras_por_categoria = {}
    for rule_path in available_pool:
        key = get_logsource_key(rule_path)
        regras_por_categoria.setdefault(key, []).append(rule_path)

    print(f" -> {len(regras_por_categoria)} categorias distintas no pool.")

    # ----------------------------------------------------------
    # PASSO 5 — Adicionar regra(s) nova(s) ao test_cases (round-robin)
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"PASSO 5: Adicionando {NEW_TEST_COUNT} nova(s) regra(s) ao test_cases...")
    print("=" * 60)

    novas_para_teste = selecionar_round_robin(regras_por_categoria, NEW_TEST_COUNT)

    adicionadas = 0
    for rule_path in novas_para_teste:
        safe_name = get_safe_filename(rule_path)
        dst_path  = os.path.join(TEST_DIR, safe_name)
        shutil.copy2(rule_path, dst_path)
        print(f" -> Adicionada: {safe_name}")
        adicionadas += 1

    total_test_final = len(nomes_em_test) + adicionadas
    print(f" -> test_cases agora tem {total_test_final} regras.")

    # ----------------------------------------------------------
    # PASSO 6 — Selecionar 10 regras extras (round-robin!)
    #           CRÍTICO: extra_test_cases é selecionado ANTES do
    #           rag_knowledge para garantir diversidade máxima.
    #           Round-robin com 10 regras e dezenas de categorias
    #           garante 10 categorias DIFERENTES no resultado.
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"PASSO 6: Selecionando {EXTRA_TEST_COUNT} regras para extra_test_cases (round-robin)...")
    print("=" * 60)

    extra_set = selecionar_round_robin(regras_por_categoria, EXTRA_TEST_COUNT)
    print(f" -> {len(extra_set)} regras extras selecionadas.")

    # ----------------------------------------------------------
    # PASSO 7 — Selecionar 75% do pool para rag_knowledge (round-robin)
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"PASSO 7: Selecionando {int(TRAIN_PERCENTAGE*100)}% do pool para rag_knowledge...")
    print("=" * 60)

    target_train = int(total_disponivel * TRAIN_PERCENTAGE)
    print(f" -> Meta: {target_train} regras ({int(TRAIN_PERCENTAGE*100)}% de {total_disponivel})")

    train_set = selecionar_round_robin(regras_por_categoria, target_train)

    if len(train_set) < target_train:
        print(f"   AVISO: pool insuficiente; foram selecionadas {len(train_set)}.")
    print(f" -> {len(train_set)} regras selecionadas para rag_knowledge.")

    # ----------------------------------------------------------
    # PASSO 8 — Gravar arquivos em disco
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("PASSO 8: Gravando arquivos em disco...")
    print("=" * 60)

    if os.path.exists(TRAIN_DIR):
        shutil.rmtree(TRAIN_DIR)
        print(f" -> rag_knowledge antiga removida.")
    os.makedirs(TRAIN_DIR, exist_ok=True)

    if os.path.exists(EXTRA_TEST_DIR):
        shutil.rmtree(EXTRA_TEST_DIR)
        print(f" -> extra_test_cases antiga removida.")
    os.makedirs(EXTRA_TEST_DIR, exist_ok=True)

    copiadas_treino = copy_files_to_dir(train_set, TRAIN_DIR)
    copiadas_extra  = copy_files_to_dir(extra_set, EXTRA_TEST_DIR)

    # ----------------------------------------------------------
    # PASSO 9 — Relatório de distribuição (AUDITORIA)
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("PASSO 9: Relatório de distribuição (auditoria de viés)")
    print("=" * 60)

    # Distribuição do repositório inteiro (referência)
    relatorio_distribuicao("REPOSITÓRIO COMPLETO", all_valid_rules, top_n=10)

    # Distribuição dos datasets gerados
    relatorio_distribuicao("rag_knowledge", train_set, top_n=10)
    relatorio_distribuicao("extra_test_cases", extra_set, top_n=10)

    # ----------------------------------------------------------
    # RESUMO FINAL
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("CONCLUÍDO — Resumo dos datasets")
    print("=" * 60)
    print(f"  test_cases       (PRESERVADA + {adicionadas} nova):  {total_test_final} regras")
    print(f"  rag_knowledge    (RECRIADA):                          {copiadas_treino} regras")
    print(f"  extra_test_cases (RECRIADA):                          {copiadas_extra} regras")
    total_usadas = total_test_final + copiadas_treino + copiadas_extra
    print(f"  Total distribuído: {total_usadas} de {total_repo} regras do repositório")
    print("=" * 60)


if __name__ == "__main__":
    main()