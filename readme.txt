agente-autonomo-rag-regras-sigma
|
|__ Diretório Sigma 	#não está nesta pasta
|   
|   
|__ src/		#pasta com os códigos para construir o agente
|   |
|   |__ Resultados/	#pasta com os códigos para análises
|   |
|   
|__ data/ 	#pasta com as regras, prompts, pareceres, planilha
|   |
|   |
|   |__ análises/
|   |   
|   |__ rag_knowledge/		#base de consulta do RAG com regras Sigma originais
|   |   
|   |__ test_cases/		#50 cenários (regras), base de teste
|   |
|   |__ extra_test_cases	#10 regras extras
|   |
|   |__ chroma_db/		#embeddings
|   |
|   
|__ prompts		#prompt que é enviado pro agente do nó 4
