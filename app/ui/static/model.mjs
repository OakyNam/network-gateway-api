export const devicePorts = { ssh: 22, netconf: 830, telnet: 23 };
export const connectorPorts = {
  ssh_tunnel: 22, ssh_shell: 22, socks5: 1080, http_connect: 8080,
};

function integer(value, label, maximum) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > maximum) {
    throw new Error(`${label} must be an integer from 1 to ${maximum}.`);
  }
  return number;
}

function text(values, name) {
  return String(values.get(name) ?? "").trim();
}

function optionalPath(values, name) {
  return text(values, name) || null;
}

function password(values, name, clearName) {
  const secret = String(values.get(name) ?? "");
  if (values.has(clearName)) {
    if (secret) throw new Error("Do not enter a new password and clear it at the same time.");
    return { password: "" };
  }
  return secret ? { password: secret } : {};
}

export function buildProfile(values, capabilities, proxies = []) {
  const protocol = text(values, "protocol");
  const proxyId = text(values, "proxy_id");
  const proxy = proxies.find((item) => item.id === proxyId);
  if (proxyId && !proxy) throw new Error("The selected proxy is unavailable. Refresh and select an existing proxy.");
  const type = values.has("proxy_id")
    ? (proxy?.type || "direct") : text(values, "connector_type");
  const connector = capabilities.connectors.find((item) => item.type === type);
  if (!connector || !connector.protocols.includes(protocol)) {
    throw new Error("This connector does not support the selected device protocol.");
  }
  const name = text(values, "name");
  const host = text(values, "host");
  if (!name || !host) throw new Error("Profile name and device host are required.");
  const clientType = text(values, "client_type") || "network";
  if (!["network", "fake"].includes(clientType)) throw new Error("Select a network or fake device client.");
  const profile = {
    name, protocol, host, client_type: clientType,
    port: integer(values.get("port"), "Device port", 65535),
    role_account_id: text(values, "role_account_id") || null,
    known_hosts_path: optionalPath(values, "known_hosts_path"),
    timeout_seconds: integer(values.get("timeout_seconds"), "Timeout", 30),
    connector: { type },
  };
  if (!profile.role_account_id) {
    Object.assign(profile, {
      username: text(values, "username"),
      private_key_path: optionalPath(values, "private_key_path"),
      ...password(values, "password", "clear_password"),
    });
  }
  if (values.has("proxy_id")) {
    profile.proxy_id = proxyId || null;
    if (proxyId) delete profile.connector;
    return profile;
  }
  if (type !== "direct") {
    const connectorHost = text(values, "connector_host");
    if (!connectorHost) throw new Error("Proxy or bastion host is required.");
    profile.connector = {
      type, host: connectorHost,
      port: integer(values.get("connector_port"), "Connector port", 65535),
      role_account_id: text(values, "connector_role_account_id") || null,
      known_hosts_path: optionalPath(values, "connector_known_hosts_path"),
    };
    if (!profile.connector.role_account_id) {
      Object.assign(profile.connector, {
        username: text(values, "connector_username"),
        private_key_path: optionalPath(values, "connector_private_key_path"),
        ...password(values, "connector_password", "clear_connector_password"),
      });
    }
  }
  return profile;
}

export function buildProxy(values, capabilities) {
  const name = text(values, "name");
  const type = text(values, "type");
  const host = text(values, "host");
  if (!name || !host) throw new Error("Proxy name and host are required.");
  if (type === "direct" || !capabilities.connectors.some((item) => item.type === type)) {
    throw new Error("Choose a supported proxy connector.");
  }
  const proxy = {
    name, type, host, port: integer(values.get("port"), "Proxy port", 65535),
    role_account_id: text(values, "role_account_id") || null,
    known_hosts_path: optionalPath(values, "known_hosts_path"),
  };
  if (!proxy.role_account_id) Object.assign(proxy, {
    username: text(values, "username"),
    private_key_path: optionalPath(values, "private_key_path"),
    ...password(values, "password", "clear_password"),
  });
  return proxy;
}

export function buildRoleAccount(values, existing = null) {
  const name = text(values, "name");
  const username = text(values, "username");
  if (!name || !username) throw new Error("Account name and username are required.");
  const authenticationType = text(values, "authentication_type");
  const account = { name, username, authentication_type: authenticationType };
  const sameType = existing?.authentication_type === authenticationType;
  if (authenticationType === "password") {
    if (text(values, "private_key") || text(values, "key_passphrase")) {
      throw new Error("Choose password or private-key authentication, not both.");
    }
    const secret = String(values.get("password") ?? "");
    if (!secret && !(sameType && existing.password_configured)) {
      throw new Error("Enter a password for this authentication method.");
    }
    if (secret) account.password = secret;
  } else if (authenticationType === "ssh_key") {
    if (String(values.get("password") ?? "")) {
      throw new Error("Choose private-key or password authentication, not both.");
    }
    const key = String(values.get("private_key") ?? "").trim();
    const passphrase = String(values.get("key_passphrase") ?? "");
    if (!key && !(sameType && existing.private_key_configured)) {
      throw new Error("Paste an SSH private key for this authentication method.");
    }
    if (!key && passphrase) {
      throw new Error("Paste the encrypted key again when changing its passphrase.");
    }
    if (key) {
      account.private_key = key;
      account.key_passphrase = passphrase;
    }
  } else {
    throw new Error("Select password or SSH private-key authentication.");
  }
  return account;
}

export function validationMessage(detail, status) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((issue) => {
      const location = Array.isArray(issue.loc) ? issue.loc.join(".") : "request";
      return `${location}: ${issue.msg || "invalid value"}`;
    }).join("; ");
  }
  return `API request failed (HTTP ${status}).`;
}
