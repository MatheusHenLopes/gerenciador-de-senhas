const readline = require("node:readline/promises");
const { stdin: input, stdout: output } = require("node:process");

const {
  encryptPassword,
  decryptPassword,
  initializeVaultSession,
  saveVaultToDisk,
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
    "Digite o nome do serviço que gostaria de adicionar: "
  );
  const cleanInputService = inputService.toLowerCase();
  
  const hasCredential = endManager.some(
    (objeto) => objeto.service === cleanInputService
  );

  if (hasCredential) {
    console.log("[ERRO]: Este serviço já está cadastrado.");
    return;
  }

  newCredential.service = cleanInputService;

  const inputUser = await validateRequiredField(
    terminal,
    "Digite o usuário ou login do serviço que gostaria de adicionar: "
  );
  newCredential.user = inputUser;

  const inputPassword = await validateRequiredField(
    terminal,
    "Digite a senha que gostaria de utilizar para o serviço: "
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
      "[" + (index + 1) + "] Serviço: " + item.service + " | Login: " + item.user + " | Senha: ********"
    );
  });
}

// OPÇÃO [3]: Busca um serviço existente com .find() e altera login/senha

async function updateCredential(terminal, endManager, masterKey, activeFile) {
  if (endManager.length === 0) {
    console.log("\n[AVISO] O cofre está vazio. Adicione uma credencial primeiro.");
    return;
  }

  const inputService = await validateRequiredField(
    terminal,
    "Digite o nome do serviço que deseja alterar: "
  );
  const cleanService = inputService.toLowerCase();

  const credentialFound = endManager.find(
    (objeto) => objeto.service === cleanService
  );

  if (!credentialFound) {
    console.log("[ERRO] Serviço não encontrado no cofre!");
    return;
  }

  console.log(
    "\nEditando [" + credentialFound.service + "] (Login atual: " + credentialFound.user + ")"
  );

  const newUser = await validateRequiredField(
    terminal,
    "Digite o NOVO usuário/login: "
  );
  const newPassword = await validateRequiredField(
    terminal,
    "Digite a NOVA senha: "
  );

  credentialFound.user = newUser;
  credentialFound.password = encryptPassword(newPassword, masterKey);

  await saveVaultToDisk(activeFile, endManager);
  console.log("[ÊXITO] Credencial recriptografada e atualizada no disco.");
}

// Função principal para interação do usuário com o terminal

async function main() {
    
  const terminal = readline.createInterface({ input, output });

  console.log("\n=== AUTENTICAÇÃO DO COFRE ===");
  const masterPassword = await validateRequiredField(
  terminal,
  "Digite sua Senha-Mestra para abrir o cofre: "
  );

  const vaultSession = await initializeVaultSession(masterPassword);
  const endManager = vaultSession.endManager;
  const masterKey = vaultSession.masterKey;
  const activeFile = vaultSession.activeFile;

  let loopExecution = true;

  while (loopExecution) {
    console.log("\n=== GERENCIADOR DE SENHAS ===");
    console.log("[1] Adicionar nova credencial");
    console.log("[2] Listar credenciais salvas");
    console.log("[3] Alterar credencial existente");
    console.log("[4] Sair");

    const menuAnswer = await terminal.question("Digite uma das opções: ");
    const cleanMenuAnswer = menuAnswer.trim();

    if (
      cleanMenuAnswer !== "1" &&
      cleanMenuAnswer !== "2" &&
      cleanMenuAnswer !== "3" &&
      cleanMenuAnswer !== "4"
    ) {
      console.log("[ERRO] Valor inválido, tente novamente.");
      continue;
    }

    if (cleanMenuAnswer === "1") {
      await addCredential(terminal, endManager, masterKey, activeFile);
      continue;
    }

    if (cleanMenuAnswer === "2") {
      listCredentials(endManager);
      continue;
    }

    if (cleanMenuAnswer === "3") {
      await updateCredential(terminal, endManager, masterKey, activeFile);
      continue;
    }

    if (cleanMenuAnswer === "4") {
      console.log("Saindo...");
      loopExecution = false;
      continue;
    }
  }
  terminal.close();
}

main();