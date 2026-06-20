=====================================================================================
PASSO 1: Lendo o repositório Sigma...
=====================================================================================
 -> 3748 regras válidas encontradas no repositório.

=====================================================================================
PASSO 2: Mapeando conjuntos preservados...
=====================================================================================
 -> test_cases:       50 arquivos.
 -> extra_test_cases: 10 arquivos.
 -> 60 regras preservadas localizadas no repositório.

=====================================================================================
PASSO 3: Construindo pool disponível...
=====================================================================================
 -> 3688 regras disponíveis
    (3748 total − 60 preservadas)
 -> 124 categorias distintas no pool.

=====================================================================================
PASSO 4: Selecionando 85% do pool para rag_knowledge...
=====================================================================================
 -> Total de regras Sigma no repositório:  3748
    (−) test_cases preservados:            50
    (−) extra_test_cases preservados:      10
    (=) Pool disponível para o RAG:        3688
 -> Quantidade esperada (85% do pool):  3134
 -> Quantidade efetivamente selecionada:   3134

=====================================================================================
PASSO 5: Gravando rag_knowledge em disco...
=====================================================================================
 -> rag_knowledge antiga removida.
 -> 3134 regras copiadas para rag_knowledge.

=====================================================================================
PASSO 6: Relatório de distribuição (auditoria de viés)
=====================================================================================

--- Distribuição de 'REPOSITÓRIO COMPLETO' (3748 regras) ---
   Categorias distintas representadas: 138
   Top 10 categorias mais frequentes:
      1409  ( 37.6%)  ██████████████████ process_creation_windows_any
       224  (  6.0%)  ██ registry_set_windows_any
       218  (  5.8%)  ██ file_event_windows_any
       178  (  4.7%)  ██ ps_script_windows_any
       170  (  4.5%)  ██ any_windows_security
       141  (  3.8%)  █ process_creation_linux_any
       123  (  3.3%)  █ image_load_windows_any
        82  (  2.2%)  █ webserver_any_any
        74  (  2.0%)   any_windows_system
        70  (  1.9%)   process_creation_macos_any

--- Distribuição de 'rag_knowledge' (3134 regras) ---
   Categorias distintas representadas: 124
   Top 10 categorias mais frequentes:
       854  ( 27.2%)  █████████████ process_creation_windows_any
       223  (  7.1%)  ███ registry_set_windows_any
       216  (  6.9%)  ███ file_event_windows_any
       177  (  5.6%)  ██ ps_script_windows_any
       168  (  5.4%)  ██ any_windows_security
       140  (  4.5%)  ██ process_creation_linux_any
       122  (  3.9%)  █ image_load_windows_any
        81  (  2.6%)  █ webserver_any_any
        74  (  2.4%)  █ any_windows_system
        69  (  2.2%)  █ process_creation_macos_any

=====================================================================================
CONCLUÍDO
=====================================================================================
  test_cases       (INTOCADO):  50 regras
  extra_test_cases (INTOCADO):  10 regras
  rag_knowledge    (RECRIADA):  3134 regras
=====================================================================================
