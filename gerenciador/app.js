const readline = require("node:readline/promises");
const { stdin: input, stdout: output } = require("node:process");

const {
  encryptPassword,
  decryptPassword,
  initializeVaultSession,
  saveVaultToDisk,
  verifyWindowsPin,
  copyToClipboardWithAutoClear,
  readAuditLog,
  clearAuditLog,
} = require("./security.js");

// Função para verificar se nenhum dos inputs digitados pelo usuário durante a adição de uma credencial saiu vazia

async function validateRequiredField(terminal, message) {
  while (true) {
    const input = await terminal.question(message);
    const cleanInput = input.trim();

    if (cleanInput !== "") {
      return cleanInput;
    }
    console.log("[ERRO]: Este campo é obrigatório.");
  }
}

// OPÇÃO [1]: Função para adição de credenciais (nome do serviço, login e senha)

async function addCredential(terminal, endManager, masterKey, activeFile) {
  const newCredential = { service: "", user: "", password: "" };

  const inputService = await validateRequiredField(
    terminal,
    "Digite o nome do serviço que gostaria de adicionar: ",
  );
  const cleanInputService = inputService.toLowerCase();

  const hasCredential = endManager.some(
    (objeto) => objeto.service === cleanInputService,
  );

  if (hasCredential) {
    console.log("[ERRO]: Este serviço já está cadastrado.");
    return;
  }

  newCredential.service = cleanInputService;

  const inputUser = await validateRequiredField(
    terminal,
    "Digite o usuário ou login do serviço que gostaria de adicionar: ",
  );
  newCredential.user = inputUser;

  const inputPassword = await validateRequiredField(
    terminal,
    "Digite a senha que gostaria de utilizar para o serviço: ",
  );

  // Criptografa a senha em AES-256-GCM antes de colocar no objeto
  newCredential.password = encryptPassword(inputPassword, masterKey);

  endManager.push(newCredential);

  // Salva a lista atualizada no arquivo JSON do HD (cofre.json ou cofre_isca.json)
  await saveVaultToDisk(activeFile, endManager);
  console.log("[ÊXITO] Credencial criptografada e salva no disco.");
}

// OPÇÃO [2]: Lista os serviços mascarando a senha na tela (Anti-Shoulder Surfing)

function listCredentials(endManager) {
  if (endManager.length === 0) {
    console.log("\n[AVISO] O cofre está vazio no momento.");
    return;
  }

  console.log("\n=== CREDENCIAIS SALVAS NO COFRE ===");
  endManager.forEach((item, index) => {
    console.log(
      "[" +
        (index + 1) +
        "] Serviço: " +
        item.service +
        " | Login: " +
        item.user +
        " | Senha: ********",
    );
  });
}

// OPÇÃO [3]: Busca um serviço existente com .find() e altera login/senha

async function updateCredential(terminal, endManager, masterKey, activeFile) {
  if (endManager.length === 0) {
    console.log(
      "\n[AVISO] O cofre está vazio. Adicione uma credencial primeiro.",
    );
    return;
  }

  const inputService = await validateRequiredField(
    terminal,
    "Digite o nome do serviço que deseja alterar: ",
  );
  const cleanService = inputService.toLowerCase();

  const credentialFound = endManager.find(
    (objeto) => objeto.service === cleanService,
  );

  if (!credentialFound) {
    console.log("[ERRO] Serviço não encontrado no cofre.");
    return;
  }

  console.log(
    "\nEditando [" +
      credentialFound.service +
      "] (Login atual: " +
      credentialFound.user +
      ")",
  );

  const newUser = await validateRequiredField(
    terminal,
    "Digite o NOVO usuário/login: ",
  );
  const newPassword = await validateRequiredField(
    terminal,
    "Digite a NOVA senha: ",
  );

  credentialFound.user = newUser;
  credentialFound.password = encryptPassword(newPassword, masterKey);

  await saveVaultToDisk(activeFile, endManager);
  console.log("[ÊXITO] Credencial recriptografada e atualizada no disco.");
}

// OPÇÃO [4]: Busca a posição do serviço com .findIndex() e remove do cofre com .splice()

async function deleteCredential(terminal, endManager, activeFile) {
  if (endManager.length === 0) {
    console.log("\n[AVISO] O cofre está vazio. Não há nada para excluir.");
    return;
  }

  const inputService = await validateRequiredField(
    terminal,
    "Digite o nome do serviço que deseja EXCLUIR: ",
  );
  const cleanService = inputService.toLowerCase();

  // Procura o número do índice (posição) onde o serviço está guardado no array
  const indexFound = endManager.findIndex(
    (objeto) => objeto.service === cleanService,
  );

  // Se devolver -1, significa que o serviço não existe no array
  if (indexFound === -1) {
    console.log("[ERRO] Serviço não encontrado no cofre.");
    return;
  }

  // Confirmação de segurança antes de apagar
  const confirmDelete = await validateRequiredField(
    terminal,
    "Tem certeza que deseja excluir [" +
      cleanService +
      "]? Digite 'sim' para confirmar: ",
  );

  if (confirmDelete.toLowerCase() !== "sim") {
    console.log("[AVISO] Exclusão cancelada pelo usuário.");
    return;
  }

  // Remove 1 item exatamente na posição encontrada e atualiza o arquivo JSON no HD
  endManager.splice(indexFound, 1);
  await saveVaultToDisk(activeFile, endManager);

  console.log("[OK] Credencial excluída permanentemente do cofre.");
}

// OPÇÃO [5]: Pede o PIN do Windows, descriptografa a senha e copia para o Ctrl+V por 15s
async function revealCredential(terminal, endManager, masterKey) {
  if (endManager.length === 0) {
    console.log("\n[AVISO] O cofre está vazio no momento.");
    return;
  }

  const inputService = await validateRequiredField(
    terminal,
    "Digite o nome do serviço que deseja acessar a senha: ",
  );
  const cleanService = inputService.toLowerCase();

  const credentialFound = endManager.find(
    (objeto) => objeto.service === cleanService,
  );

  if (!credentialFound) {
    console.log("[ERRO] Serviço não encontrado no cofre.");
    return;
  }

  console.log(
    "\n[AGUARDANDO] Confirme o PIN de segurança do Windows na janela do sistema...",
  );
  const isPinVerified = await verifyWindowsPin();

  if (isPinVerified === false) {
    console.log(
      "[ACESSO NEGADO] PIN do Windows incorreto ou cancelado! Incidente registrado no log.",
    );
    return;
  }

  // Se o Windows aprovou o PIN, descriptografa a senha na memória RAM
  const plainPassword = await decryptPassword(
    credentialFound.password,
    masterKey,
    credentialFound.service,
  );

  if (plainPassword === null) {
    console.log(
      "[ALERTA CRITICO] Falha de integridade: O arquivo cofre.json foi adulterado.",
    );
    return;
  }

  // Copia a senha para o Ctrl+V sem mostrar na tela (ou mostrando se preferir)
  copyToClipboardWithAutoClear(plainPassword);

  console.log("[OK] Identidade confirmada pelo Windows.");
  console.log(
    "Servico: " + credentialFound.service + " | Login: " + credentialFound.user,
  );
  console.log(
    "[SEGURANCA] A senha NÃO foi exibida na tela para evitar espionagem visual.",
  );
  console.log(
    "[CTRL+V] Senha copiada para a área de transferência. Ela será apagada em 15 segundos.",
  );
}

// OPÇÃO [6]: Exibe o arquivo auditoria.log no terminal e permite limpar usando o PIN do Windows
async function manageAuditLog(terminal, isHoneypot) {
  console.log("\n=== REGISTROS DE AUDITORIA E SEGURANCA ===");

  // Se estiver no Cofre Isca (Honeypot), esconde os alertas reais para não alertar o invasor!
  if (isHoneypot === true) {
    console.log("Nenhum incidente de seguranca registrado ate o momento.");
    return;
  }

  const currentLogs = await readAuditLog();
  console.log(currentLogs);
  console.log("----------------------------------------");

  const answer = await terminal.question(
    "Deseja LIMPAR o historico de logs? Digite 'sim' para apagar ou ENTER para voltar: ",
  );

  if (answer.trim().toLowerCase() !== "sim") {
    return;
  }

  console.log(
    "\n[AGUARDANDO] Confirme o PIN do Windows para autorizar a limpeza do log...",
  );
  const isPinVerified = await verifyWindowsPin();

  if (isPinVerified === false) {
    console.log(
      "[ACESSO NEGADO] PIN incorreto. A tentativa de apagar os logs foi registrada.",
    );
    return;
  }

  await clearAuditLog();
  console.log("[OK] Historico de auditoria limpo com sucesso.");
}

// Função principal para interação do usuário com o terminal

async function main() {
  const terminal = readline.createInterface({ input, output });

  console.clear();
  console.log("=================================");
  console.log("      AUTENTICACAO DO COFRE      ");
  console.log("=================================");

  const masterPassword = await validateRequiredField(
    terminal,
    "Digite sua Senha-Mestra para abrir o cofre: ",
  );

  const vaultSession = await initializeVaultSession(masterPassword);

  // Guard Clause da Porta de Entrada: Barra se a Senha-Mestra estiver errada ou se o JSON foi adulterado
  if (vaultSession === null) {
    console.log(
      "\n[ACESSO NEGADO] Senha-Mestra incorreta ou arquivo do cofre corrompido!",
    );
    console.log(
      "[AUDITORIA] O incidente foi gravado no arquivo auditoria.log.",
    );
    terminal.close();
    return;
  }

  const endManager = vaultSession.endManager;
  const masterKey = vaultSession.masterKey;
  const activeFile = vaultSession.activeFile;
  const isHoneypot = vaultSession.isHoneypot;

  let loopExecution = true;

  while (loopExecution) {
    console.clear();
    console.log("========================================");
    console.log("         GERENCIADOR DE SENHAS          ");
    console.log("========================================");
    console.log("[1] Adicionar nova credencial");
    console.log("[2] Listar credenciais salvas");
    console.log("[3] Alterar credencial existente");
    console.log("[4] Excluir credencial");
    console.log("[5] Acessar senhas (Requer PIN)");
    console.log("[6] Manipular o Log (Requer PIN)");
    console.log("[7] Sair");
    console.log("----------------------------------------");

    const menuAnswer = await terminal.question("Digite uma das opcoes: ");
    const cleanMenuAnswer = menuAnswer.trim();

    // 1. Validação atualizada de 1 até 6

    if (
      cleanMenuAnswer !== "1" &&
      cleanMenuAnswer !== "2" &&
      cleanMenuAnswer !== "3" &&
      cleanMenuAnswer !== "4" &&
      cleanMenuAnswer !== "5" &&
      cleanMenuAnswer !== "6" &&
      cleanMenuAnswer !== "7"
    ) {
      console.log("\n[ERRO] Valor invalido, tente novamente.");
      console.log("----------------------------------------");
      await terminal.question("Pressione ENTER para continuar...");
      continue;
    }

    // 2. Execução de cada opção do menu

    if (cleanMenuAnswer === "1") {
      await addCredential(terminal, endManager, masterKey, activeFile);
      console.log("----------------------------------------");
      await terminal.question("Pressione ENTER para voltar ao menu...");
      continue;
    }

    if (cleanMenuAnswer === "2") {
      listCredentials(endManager);
      console.log("----------------------------------------");
      await terminal.question("Pressione ENTER para voltar ao menu...");
      continue;
    }

    if (cleanMenuAnswer === "3") {
      await updateCredential(terminal, endManager, masterKey, activeFile);
      console.log("----------------------------------------");
      await terminal.question("Pressione ENTER para voltar ao menu...");
      continue;
    }

    if (cleanMenuAnswer === "4") {
      await deleteCredential(terminal, endManager, activeFile);
      console.log("----------------------------------------");
      await terminal.question("Pressione ENTER para voltar ao menu...");
      continue;
    }

    if (cleanMenuAnswer === "5") {
      await revealCredential(terminal, endManager, masterKey);
      console.log("----------------------------------------");
      await terminal.question("Pressione ENTER para voltar ao menu...");
      continue;
    }

    if (cleanMenuAnswer === "6") {
      await manageAuditLog(terminal, isHoneypot);
      console.log("----------------------------------------");
      await terminal.question("Pressione ENTER para voltar ao menu...");
      continue;
    }

    if (cleanMenuAnswer === "7") {
      console.log("\nEncerrando o cofre com seguranca...");
      loopExecution = false;
      continue;
    }
  }
  terminal.close();
}

main();
