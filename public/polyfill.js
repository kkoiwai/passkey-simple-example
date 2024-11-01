class base64url {
    static encode(buffer) {
        const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }

    static decode(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const binStr = window.atob(base64);
        const bin = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
            bin[i] = binStr.charCodeAt(i);
        }
        return bin.buffer;
    }
}

if (PublicKeyCredential) {
    if (!PublicKeyCredential?.parseCreationOptionsFromJSON) {
        PublicKeyCredential.parseCreationOptionsFromJSON = (options) => {
            const user = {
                ...options.user,
                id: base64url.decode(options.user.id),
            };
            const challenge = base64url.decode(options.challenge);
            const excludeCredentials =
                options.excludeCredentials?.map((cred) => {
                    return {
                        ...cred,
                        id: base64url.decode(cred.id),
                    };
                }) ?? [];
            return {
                ...options,
                user,
                challenge,
                excludeCredentials,
            };
        };
    }

    if (!PublicKeyCredential?.parseRequestOptionsFromJSON) {
        PublicKeyCredential.parseRequestOptionsFromJSON = (options) => {
            const challenge = base64url.decode(options.challenge);
            const allowCredentials =
                options.allowCredentials?.map((cred) => {
                    return {
                        ...cred,
                        id: base64url.decode(cred.id),
                    };
                }) ?? [];
            return {
                ...options,
                allowCredentials,
                challenge,
            };
        };
    }

    if (!PublicKeyCredential.prototype.toJSON) {
        PublicKeyCredential.prototype.toJSON = function () {
            try {
                const id = this.id;
                const rawId = base64url.encode(this.rawId);
                const authenticatorAttachment = this.authenticatorAttachment;
                const clientExtensionResults = {};
                const type = this.type;
                // This is authentication.
                if (this.response.signature) {
                    return {
                        id,
                        rawId,
                        response: {
                            authenticatorData: base64url.encode(this.response.authenticatorData),
                            clientDataJSON: base64url.encode(this.response.clientDataJSON),
                            signature: base64url.encode(this.response.signature),
                            userHandle: base64url.encode(this.response.userHandle),
                        },
                        authenticatorAttachment,
                        clientExtensionResults,
                        type,
                    };
                } else {
                    return {
                        id,
                        rawId,
                        response: {
                            clientDataJSON: base64url.encode(this.response.clientDataJSON),
                            attestationObject: base64url.encode(this.response.attestationObject),
                            transports: this.response?.getTransports() || [],
                        },
                        authenticatorAttachment,
                        clientExtensionResults,
                        type,
                    };
                }
            } catch (error) {
                console.error(error);
                throw error;
            }
        }
    }
}