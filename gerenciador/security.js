const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const childProcess = require("node:child_process");

// Configurações de arquivos e segurança em camelCase
const realVaultFile = "./cofre.json";
const honeypotVaultFile = "./cofre-isca.json";
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
  const ivBuffer = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, ivBuffer);

  let encryptedPassword = cipher.update(plainPassword, "utf8", "hex");
  encryptedPassword = encryptedPassword + cipher.final("hex");

  const authTagBuffer = cipher.getAuthTag();

  const ivHex = ivBuffer.toString("hex");
  const authTagHex = authTagBuffer.toString("hex");

  const finalPayload = ivHex + ":" + authTagHex + ":" + encryptedPassword;
  return finalPayload;
}

// 4. Descriptografa a senha e verifica se o arquivo JSON não foi adulterado
async function decryptPassword(encryptedPayload, masterKey, serviceName) {
  try {
    const parts = encryptedPayload.split(":");

    if (parts.length !== 3) {
      throw new Error("Formato inválido no arquivo JSON.");
    }

    const ivBuffer = Buffer.from(parts[0], "hex");
    const authTagBuffer = Buffer.from(parts[1], "hex");
    const encryptedText = parts[2];

    const decipher = crypto.createDecipheriv("aes-256-gcm", masterKey, ivBuffer);
    decipher.setAuthTag(authTagBuffer);

    let decryptedPassword = decipher.update(encryptedText, "hex", "utf8");
    decryptedPassword = decryptedPassword + decipher.final("utf8");

    return decryptedPassword;
  } catch (error) {
    await logSecurityEvent(
      "VIOLACAO_DE_INTEGRIDADE_OU_CHAVE",
      "Falha ao descriptografar o servico: " + serviceName + ". Chave incorreta ou arquivo JSON adulterado."
    );
    return null;
  }
}

// 5. Abre o cofre no início e valida se a Senha-Mestra está correta
async function initializeVaultSession(masterPassword) {
  const masterKey = deriveMasterKey(masterPassword);
  let isHoneypot = false;
  let activeFile = realVaultFile;

  if (masterPassword === duressPassword) {
    isHoneypot = true;
    activeFile = honeypotVaultFile;

    await logSecurityEvent(
      "ALERTA_COACAO_HONEYPOT",
      "Senha de coacao digitada! Carregando Cofre Isca falso para proteger os dados reais."
    );
  }

  try {
    const fileContent = await fs.readFile(activeFile, "utf-8");
    const savedList = JSON.parse(fileContent);

    // Se já existem senhas salvas no cofre, testa destrancar a primeira para validar a Senha-Mestra!
    if (savedList.length > 0) {
      const testUnlock = await decryptPassword(
        savedList[0].password,
        masterKey,
        savedList[0].service
      );

      if (testUnlock === null) {
        return null; // Senha-Mestra incorreta ou cofre adulterado!
      }
    }

    return {
      endManager: savedList,
      masterKey: masterKey,
      activeFile: activeFile,
      isHoneypot: isHoneypot,
    };
  } catch (error) {
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

    return {
      endManager: [],
      masterKey: masterKey,
      activeFile: activeFile,
      isHoneypot: isHoneypot,
    };
  }
}

// 6. Salva a lista endManager atualizada dentro do arquivo JSON no HD
async function saveVaultToDisk(activeFile, endManager) {
  const jsonText = JSON.stringify(endManager, null, 2);
  await fs.writeFile(activeFile, jsonText, "utf-8");
}

// 7. Chama a janela oficial de PIN/Biometria do Windows e espera o usuário digitar
async function verifyWindowsPin() {
  try {
    const psCommand =
      "Add-Type -AssemblyName System.Runtime.WindowsRuntime; " +
      "$null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]; " +
      "$null = [Windows.Security.Credentials.UI.UserConsentVerificationResult, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]; " +
      "$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('Confirme seu PIN para liberar a senha do cofre'); " +
      "$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -like 'IAsyncOperation*' })[0]; " +
      "$asTask = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult]); " +
      "$netTask = $asTask.Invoke($null, @($op)); " +
      "$netTask.Wait(-1) | Out-Null; " +
      "if ($netTask.Result -eq 'Verified') { exit 0 } else { exit 1 }";

    childProcess.execFileSync(
      "powershell",
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCommand],
      { stdio: "ignore" }
    );

    return true;
  } catch (error) {
    await logSecurityEvent(
      "FALHA_AUTENTICACAO_WINDOWS_PIN",
      "O usuario errou ou cancelou o PIN de seguranca do Windows Hello."
    );
    return false;
  }
}

  // 8. Copia a senha para o Ctrl+V do Windows e limpa sozinho após 15 segundos
  function copyToClipboardWithAutoClear(plainPassword) {
    try {
      // Envia a senha por um tubo isolado de memória (input) sem travar o teclado do terminal
      childProcess.execFileSync(
        "powershell",
        [
          "-NoProfile",
          "-Command",
          "$senha = [Console]::In.ReadToEnd(); Set-Clipboard -Value $senha",
        ],
        {
          input: plainPassword,
          stdio: ["pipe", "ignore", "ignore"],
        }
      );

      // Agenda a limpeza automática do Ctrl+V para daqui a 15 segundos em segundo plano
      const timer = setTimeout(() => {
        childProcess.execFile(
          "powershell",
          ["-NoProfile", "-Command", "Set-Clipboard -Value $null"],
          { stdio: "ignore" },
          () => {}
        );
      }, 15000);

      // Permite que o programa feche normalmente mesmo se o usuário sair antes dos 15s
      timer.unref();
      return true;
    } catch (error) {
      return false;
  }
}

// 9. Lê o conteúdo do arquivo auditoria.log para mostrar no terminal
async function readAuditLog() {
  try {
    const logContent = await fs.readFile(auditLogFile, "utf-8");
    if (logContent.trim() === "") {
      return "Nenhum incidente registrado no log.";
    }
    return logContent;
  } catch (error) {
    return "Nenhum incidente registrado no log ate o momento.";
  }
}

  // 10. Apaga o histórico do auditoria.log e registra o evento de limpeza

  async function clearAuditLog() {
  await fs.writeFile(auditLogFile, "", "utf-8");
  await logSecurityEvent(
    "AUDITORIA_REINICIADA",
    "Historico de logs limpo pelo administrador apos confirmacao de PIN."
  );
}

module.exports = {
  encryptPassword,
  decryptPassword,
  initializeVaultSession,
  saveVaultToDisk,
  logSecurityEvent,
  verifyWindowsPin,
  copyToClipboardWithAutoClear,
  readAuditLog,
  clearAuditLog,
};