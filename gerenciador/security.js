const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");

// Configurações de arquivos e segurança em camelCase
const realVaultFile = "./cofre.json";
const honeypotVaultFile = "./cofre_isca.json";
const auditLogFile = "./auditoria.log";

const vaultSalt = "ETEP_CYBERSEC_SALT_2026";
const duressPassword = "isca123";

// 1. Registra eventos de segurança no arquivo auditoria.log usando dados do Sistema Operacional
async function logSecurityEvent(eventType, details) {
  const currentDate = new Date().toLocaleString("pt-BR");
  const systemUser = os.userInfo().username;
  const machineName = os.hostname();

  const logLine =
    "[" + currentDate + "] " +
    "[PC: " + machineName + " | User: " + systemUser + "] " +
    "[" + eventType + "] -> " + details + "\n";

  await fs.appendFile(auditLogFile, logLine, "utf-8");
}

// 2. Transforma a Senha-Mestra digitada em uma chave de 32 bytes na memória RAM
function deriveMasterKey(masterPassword) {
  const keyBuffer = crypto.scryptSync(masterPassword, vaultSalt, 32);
  return keyBuffer;
}

// 3. Criptografa a senha com AES-256-GCM
function encryptPassword(plainPassword, masterKey) {
  // Sorteia 12 bytes aleatórios (IV) para que duas senhas iguais nunca fiquem iguais no JSON
  const ivBuffer = crypto.randomBytes(12);

  // Cria a máquina de criptografia com o algoritmo, a chave de 32 bytes e o IV
  const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, ivBuffer);

  // Passa a senha pela máquina (de texto utf8 para hexadecimal) e finaliza o bloco
  let encryptedPassword = cipher.update(plainPassword, "utf8", "hex");
  encryptedPassword = encryptedPassword + cipher.final("hex");

  // Pega o selo matemático de integridade (AuthTag) gerado pelo modo GCM
  const authTagBuffer = cipher.getAuthTag();

  // Converte os buffers binários do IV e da AuthTag para texto hexadecimal
  const ivHex = ivBuffer.toString("hex");
  const authTagHex = authTagBuffer.toString("hex");

  // Junta as 3 partes separadas por dois-pontos para salvar no JSON
  const finalPayload = ivHex + ":" + authTagHex + ":" + encryptedPassword;
  return finalPayload;
}

// 4. Descriptografa a senha e verifica se o arquivo cofre.json não foi adulterado
async function decryptPassword(encryptedPayload, masterKey, serviceName) {
  try {
    // Divide o texto "iv:authTag:senhaCifrada" onde tem dois-pontos
    const parts = encryptedPayload.split(":");

    if (parts.length !== 3) {
      throw new Error("Formato inválido no arquivo JSON.");
    }

    // Transforma o IV e a AuthTag de texto hexadecimal de volta para bytes na RAM (Buffer)
    const ivBuffer = Buffer.from(parts[0], "hex");
    const authTagBuffer = Buffer.from(parts[1], "hex");
    const encryptedText = parts[2];

    // Cria a máquina de descriptografia e entrega o selo de integridade (AuthTag)
    const decipher = crypto.createDecipheriv("aes-256-gcm", masterKey, ivBuffer);
    decipher.setAuthTag(authTagBuffer);

    // Tenta destrancar a senha. Se 1 letra foi alterada no JSON, o .final() explode erro aqui!
    let decryptedPassword = decipher.update(encryptedText, "hex", "utf8");
    decryptedPassword = decryptedPassword + decipher.final("utf8");

    return decryptedPassword;
  } catch (error) {
    // Se caiu no catch, a Senha-Mestra está errada ou tentaram hackear o arquivo cofre.json!
    await logSecurityEvent(
      "VIOLACAO_DE_INTEGRIDADE",
      "Falha ao abrir o servico: " + serviceName + ". Senha-Mestra incorreta ou arquivo JSON adulterado."
    );
    return null;
  }
}

// 5. Abre o cofre no início do programa (decide entre Cofre Real ou Cofre Isca/Honeypot)
async function initializeVaultSession(masterPassword) {
  const masterKey = deriveMasterKey(masterPassword);
  let isHoneypot = false;
  let activeFile = realVaultFile;

  // Se o usuário digitou a senha de coação ("911"), troca silenciosamente para o Cofre Isca
  if (masterPassword === duressPassword) {
    isHoneypot = true;
    activeFile = honeypotVaultFile;

    await logSecurityEvent(
      "ALERTA_COACAO_HONEYPOT",
      "Senha de coacao digitada! Carregando Cofre Isca falso para proteger os dados reais."
    );
  }

  // Tenta ler o arquivo do cofre no HD. Se ainda não existir, cai no catch e cria um novo
  try {
    const fileContent = await fs.readFile(activeFile, "utf-8");
    const savedList = JSON.parse(fileContent);

    return {
      endManager: savedList,
      masterKey: masterKey,
      activeFile: activeFile,
      isHoneypot: isHoneypot,
    };
  } catch (error) {
    // Se entrou aqui, é a primeira vez que o programa está abrindo esse cofre
    if (isHoneypot === true) {
      const fakeCredentials = [
        {
          service: "banrisul",
          user: "matheus.lopes",
          password: encryptPassword("SenhaFalsaBanco123", masterKey),
        },
        {
          service: "gmail",
          user: "matheus@gmail.com",
          password: encryptPassword("IscaDeSeguranca99", masterKey),
        },
      ];

      await saveVaultToDisk(activeFile, fakeCredentials);

      return {
        endManager: fakeCredentials,
        masterKey: masterKey,
        activeFile: activeFile,
        isHoneypot: isHoneypot,
      };
    }

    // Se for o cofre real e o arquivo ainda não existir, começa com uma lista vazia []
    return {
      endManager: [],
      masterKey: masterKey,
      activeFile: activeFile,
      isHoneypot: isHoneypot,
    };
  }
}

// 6. Salva a lista endManager atualizada dentro do arquivo JSON no Disco Rígido
async function saveVaultToDisk(activeFile, endManager) {
  const jsonText = JSON.stringify(endManager, null, 2);
  await fs.writeFile(activeFile, jsonText, "utf-8");
}

module.exports = {
  encryptPassword,
  decryptPassword,
  initializeVaultSession,
  saveVaultToDisk,
  logSecurityEvent,
};