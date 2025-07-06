# BOTOES E FUNCOES
# # Cria os dois checkboxes para os IPs
ping_1 = st.checkbox("1.1.1.1", key="ip1")
ping_2 = st.checkbox("8.8.8.8", key="ip2") 

# Botão para executar a ação
if st.button("Executar"):
    # Verifica se os dois checkboxes foram marcados
    if ping_1 and ping_2:
        st.error("Só pode marcar uma caixa por vez.")
    # Verifica se nenhum checkbox foi marcado
    elif not (ping_1 or ping_2):
        st.warning("Selecione um IP para executar o ping.")
    else:
        # Define o IP com base no checkbox marcado
        ip = "1.1.1.1" if ping_1 else "8.8.8.8"
        # Executa o ping (comando para sistemas Linux; em Windows use "-n" em vez de "-c")
        resultado = subprocess.run(["ping", "-c", "5", ip], capture_output=True, text=True)
        # Exibe o resultado em uma caixa de texto com estilo shell
        st.text_area("Resultado do Ping", resultado.stdout, height=300)
