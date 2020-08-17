/********************************************************************************
 * Copyright (C) 2020 Red Hat, Inc. and others.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the Eclipse
 * Public License v. 2.0 are satisfied: GNU General Public License, version 2
 * with the GNU Classpath Exception which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 ********************************************************************************/

import { interfaces } from 'inversify';
import { AuthenticationExt, AuthenticationMain, MAIN_RPC_CONTEXT } from '../../common/plugin-api-rpc';
import { RPCProtocol } from '../../common/rpc-protocol';
import { Disposable } from '@theia/core/lib/common/disposable';
import { MessageService } from '@theia/core/lib/common/message-service';
import { StorageService } from '@theia/core/lib/browser';
import {
    AuthenticationProvider,
    AuthenticationService,
    AuthenticationSessionsChangeEvent, readAllowedExtensions
} from '@theia/authentication/lib/browser/authentication-service';
import { AuthenticationSession } from '../../plugin/types-impl';

export class AuthenticationMainImpl implements AuthenticationMain {
    private readonly proxy: AuthenticationExt;
    private readonly messageService: MessageService;
    private readonly storageService: StorageService;
    private readonly authenticationService: AuthenticationService;
    constructor(rpc: RPCProtocol, container: interfaces.Container) {
        this.proxy = rpc.getProxy(MAIN_RPC_CONTEXT.AUTHENTICATION_EXT);
        this.messageService = container.get(MessageService);
        this.storageService = container.get(StorageService);
        this.authenticationService = container.get(AuthenticationService);

        this.authenticationService.onDidChangeSessions(e => {
            this.proxy.$onDidChangeAuthenticationSessions(e.providerId, e.event);
        });
        this.authenticationService.onDidRegisterAuthenticationProvider(providerId => {
            this.proxy.$onDidChangeAuthenticationProviders([providerId], []);
        });
        this.authenticationService.onDidUnregisterAuthenticationProvider(providerId => {
            this.proxy.$onDidChangeAuthenticationProviders([], [providerId]);
        });
    }
    $getProviderIds(): Promise<string[]> {
        return Promise.resolve(this.authenticationService.getProviderIds());
    }

    async $registerAuthenticationProvider(id: string, displayName: string, supportsMultipleAccounts: boolean): Promise<void> {
        const provider = new AuthenticationProviderImp(this.proxy, id, displayName, supportsMultipleAccounts, this.storageService, this.messageService);
        await provider.initialize();
        this.authenticationService.registerAuthenticationProvider(id, provider);
    }

    async $unregisterAuthenticationProvider(id: string): Promise<void> {
        this.authenticationService.unregisterAuthenticationProvider(id);
    }

    async $sendDidChangeSessions(id: string, event: AuthenticationSessionsChangeEvent): Promise<void> {
        this.authenticationService.sessionsUpdate(id, event);
    }

    $getSessions(id: string): Promise<ReadonlyArray<AuthenticationSession>> {
        return this.authenticationService.getSessions(id);
    }

    $login(providerId: string, scopes: string[]): Promise<AuthenticationSession> {
        return this.authenticationService.login(providerId, scopes);
    }

    $logout(providerId: string, sessionId: string): Promise<void> {
        return this.authenticationService.logout(providerId, sessionId);
    }

    async $requestNewSession(providerId: string, scopes: string[], extensionId: string, extensionName: string): Promise<void> {
        return this.authenticationService.requestNewSession(providerId, scopes, extensionId, extensionName);
    }

    async $getSession(providerId: string, scopes: string[], extensionId: string, extensionName: string,
                      options: { createIfNone: boolean, clearSessionPreference: boolean }): Promise<AuthenticationSession | undefined> {
        const orderedScopes = scopes.sort().join(' ');
        const sessions = (await this.$getSessions(providerId)).filter(session => session.scopes.sort().join(' ') === orderedScopes);
        const displayName = this.authenticationService.getDisplayName(providerId);

        if (sessions.length) {
            if (!this.authenticationService.supportsMultipleAccounts(providerId)) {
                const session = sessions[0];
                const allowed = await this.$getSessionsPrompt(providerId, session.account.displayName, displayName, extensionId, extensionName);
                if (allowed) {
                    return session;
                } else {
                    throw new Error('User did not consent to login.');
                }
            }

            // On renderer side, confirm consent, ask user to choose between accounts if multiple sessions are valid
            const selected = await this.$selectSession(providerId, displayName, extensionId, extensionName, sessions, scopes, options.clearSessionPreference);
            return sessions.find(session => session.id === selected.id);
        } else {
            if (options.createIfNone) {
                const isAllowed = await this.$loginPrompt(displayName, extensionName);
                if (!isAllowed) {
                    throw new Error('User did not consent to login.');
                }

                const session = await this.authenticationService.login(providerId, scopes);
                await this.$setTrustedExtension(providerId, session.account.displayName, extensionId, extensionName);
                return session;
            } else {
                await this.$requestNewSession(providerId, scopes, extensionId, extensionName);
                return undefined;
            }
        }
    }

    async $selectSession(providerId: string, providerName: string, extensionId: string, extensionName: string,
                         potentialSessions: AuthenticationSession[], scopes: string[], clearSessionPreference: boolean): Promise<AuthenticationSession> {
        if (!potentialSessions.length) {
            throw new Error('No potential sessions found');
        }

        if (clearSessionPreference) {
            await this.storageService.setData(`${extensionName}-${providerId}`, undefined);
        } else {
            const existingSessionPreference = await this.storageService.getData(`${extensionName}-${providerId}`);
            if (existingSessionPreference) {
                const matchingSession = potentialSessions.find(session => session.id === existingSessionPreference);
                if (matchingSession) {
                    const allowed = await this.$getSessionsPrompt(providerId, matchingSession.account.displayName, providerName, extensionId, extensionName);
                    if (allowed) {
                        return matchingSession;
                    }
                }
            }
        }

        return new Promise((resolve, reject) => {
            // const quickPick = this.quickInputService.createQuickPick<{ label: string, session?: AuthenticationSession }>();
            // quickPick.ignoreFocusOut = true;
            // const items: { label: string, session?: AuthenticationSession }[] = potentialSessions.map(session => {
            //     return {
            //         label: session.account.displayName,
            //         session
            //     };
            // });
            //
            // items.push({
            //     label: nls.localize('useOtherAccount', "Sign in to another account")
            // });
            //
            // quickPick.items = items;
            // quickPick.title = nls.localize(
            //     {
            //         key: 'selectAccount',
            //         comment: ['The placeholder {0} is the name of an extension. {1} is the name of the type of account, such as Microsoft or GitHub.']
            //     },
            //     "The extension '{0}' wants to access a {1} account",
            //     extensionName,
            //     providerName);
            // quickPick.placeholder = nls.localize('getSessionPlateholder', "Select an account for '{0}' to use or Esc to cancel", extensionName);
            //
            // quickPick.onDidAccept(async _ => {
            //     const selected = quickPick.selectedItems[0];
            //
            //     const session = selected.session ?? await this.authenticationService.login(providerId, scopes);
            //
            //     const accountName = session.account.displayName;
            //
            //     const allowList = readAllowedExtensions(this.storageService, providerId, accountName);
            //     if (!allowList.find(allowed => allowed.id === extensionId)) {
            //         allowList.push({ id: extensionId, name: extensionName });
            //         this.storageService.store(`${providerId}-${accountName}`, JSON.stringify(allowList), StorageScope.GLOBAL);
            //     }
            //
            //     this.storageService.store(`${extensionName}-${providerId}`, session.id, StorageScope.GLOBAL);
            //
            //     quickPick.dispose();
            //     resolve(session);
            // });
            //
            // quickPick.onDidHide(_ => {
            //     if (!quickPick.selectedItems[0]) {
            //         reject('User did not consent to account access');
            //     }
            //
            //     quickPick.dispose();
            // });
            //
            // quickPick.show();
        });
    }

    async $getSessionsPrompt(providerId: string, accountName: string, providerName: string, extensionId: string, extensionName: string): Promise<boolean> {
        const allowList = await readAllowedExtensions(this.storageService, providerId, accountName);
        const extensionData = allowList.find(extension => extension.id === extensionId);
        if (extensionData) {
            addAccountUsage(this.storageService, providerId, accountName, extensionId, extensionName);
            return true;
        }

        // const remoteConnection = this.remoteAgentService.getConnection();
        // if (remoteConnection && remoteConnection.remoteAuthority && remoteConnection.remoteAuthority.startsWith('vsonline') && VSO_ALLOWED_EXTENSIONS.includes(extensionId)) {
        //     addAccountUsage(this.storageService, providerId, accountName, extensionId, extensionName);
        //     return true;
        // }

        // const { choice } = await this.dialogService.show(
        //     Severity.Info,
        //     nls.localize('confirmAuthenticationAccess', "The extension '{0}' wants to access the {1} account '{2}'.", extensionName, providerName, accountName),
        //     [nls.localize('allow', "Allow"), nls.localize('cancel', "Cancel")],
        //     {
        //         cancelId: 1
        //     }
        // );
        const choice = await this.messageService.info(`The extension '${extensionName}' wants to access the ${providerName} account '${accountName}'.`, 'Allow', 'Cancel');

        const allow = choice === 'Allow';
        if (allow) {
            await addAccountUsage(this.storageService, providerId, accountName, extensionId, extensionName);
            allowList.push({ id: extensionId, name: extensionName });
            this.storageService.setData(`${providerId}-${accountName}`, JSON.stringify(allowList));
        }

        return allow;
    }

    async $loginPrompt(providerName: string, extensionName: string): Promise<boolean> {
        // const { choice } = await this.dialogService.show(
        //     Severity.Info,
        //     nls.localize('confirmLogin', "The extension '{0}' wants to sign in using {1}.", extensionName, providerName),
        //     [nls.localize('allow', "Allow"), nls.localize('cancel', "Cancel")],
        //     {
        //         cancelId: 1
        //     }
        // );
        const choice = await this.messageService.info(`The extension '${extensionName}' wants to sign in using ${providerName}.`, 'Allow', 'Cancel');
        return choice === 'Allow';
    }

    async $setTrustedExtension(providerId: string, accountName: string, extensionId: string, extensionName: string): Promise<void> {
        const allowList = await readAllowedExtensions(this.storageService, providerId, accountName);
        if (!allowList.find(allowed => allowed.id === extensionId)) {
            allowList.push({ id: extensionId, name: extensionName });
            this.storageService.setData(`${providerId}-${accountName}`, JSON.stringify(allowList));
        }
    }
}

async function addAccountUsage(storageService: StorageService, providerId: string, accountName: string, extensionId: string, extensionName: string): Promise<void> {
    const accountKey = `${providerId}-${accountName}-usages`;
    const usages = await readAccountUsages(storageService, providerId, accountName);

    const existingUsageIndex = usages.findIndex(usage => usage.extensionId === extensionId);
    if (existingUsageIndex > -1) {
        usages.splice(existingUsageIndex, 1, {
            extensionId,
            extensionName,
            lastUsed: Date.now()
        });
    } else {
        usages.push({
            extensionId,
            extensionName,
            lastUsed: Date.now()
        });
    }

    await storageService.setData(accountKey, JSON.stringify(usages));
}

interface AccountUsage {
    extensionId: string;
    extensionName: string;
    lastUsed: number;
}

export class AuthenticationProviderImp implements AuthenticationProvider, Disposable {
    private _accounts = new Map<string, string[]>(); // Map account name to session ids
    private _sessions = new Map<string, string>(); // Map account id to name

    constructor(
        private readonly proxy: AuthenticationExt,
        public readonly id: string,
        public readonly displayName: string,
        public readonly supportsMultipleAccounts: boolean,
        private readonly storageService: StorageService,
        private readonly messageService: MessageService
    ) {
    }

    public async initialize(): Promise<void> {
        return this.registerCommandsAndContextMenuItems();
    }

    public hasSessions(): boolean {
        return !!this._sessions.size;
    }

    private async registerCommandsAndContextMenuItems(): Promise<void> {
        const sessions = await this.proxy.$getSessions(this.id);
        sessions.forEach(session => this.registerSession(session));
    }

    private registerSession(session: AuthenticationSession): void {
        this._sessions.set(session.id, session.account.displayName);

        const existingSessionsForAccount = this._accounts.get(session.account.displayName);
        if (existingSessionsForAccount) {
            this._accounts.set(session.account.displayName, existingSessionsForAccount.concat(session.id));
            return;
        } else {
            this._accounts.set(session.account.displayName, [session.id]);
        }

        // this.storageKeysSyncRegistryService.registerStorageKey({ key: `${this.id}-${session.account.displayName}`, version: 1 });
    }

    async signOut(accountName: string): Promise<void> {
        const accountUsages = await readAccountUsages(this.storageService, this.id, accountName);
        const sessionsForAccount = this._accounts.get(accountName);

        // const result = await this.dialogService.confirm({
        //     title: nls.localize('signOutConfirm', "Sign out of {0}", accountName),
        //     message: accountUsages.length
        //         ? nls.localize('signOutMessagve', "The account {0} has been used by: \n\n{1}\n\n Sign out of these features?",
        //         accountName, accountUsages.map(usage => usage.extensionName).join('\n'))
        //         : nls.localize('signOutMessageSimple', "Sign out of {0}?", accountName)
        // });

        const result = await this.messageService.info(`The account ${accountName} has been used by: \\n\\n
        ${accountUsages.map(usage => usage.extensionName).join('\n')}\\n\\n Sign out of these features?`, 'Yes');

        if (result && result === 'Yes' && sessionsForAccount) {
            sessionsForAccount.forEach(sessionId => this.logout(sessionId));
            removeAccountUsage(this.storageService, this.id, accountName);
        }
    }

    async getSessions(): Promise<ReadonlyArray<AuthenticationSession>> {
        return this.proxy.$getSessions(this.id);
    }

    async updateSessionItems(event: AuthenticationSessionsChangeEvent): Promise<void> {
        const { added, removed } = event;
        const session = await this.proxy.$getSessions(this.id);
        const addedSessions = session.filter(s => added.some(id => id === s.id));

        removed.forEach(sessionId => {
            const accountName = this._sessions.get(sessionId);
            if (accountName) {
                this._sessions.delete(sessionId);
                const sessionsForAccount = this._accounts.get(accountName) || [];
                const sessionIndex = sessionsForAccount.indexOf(sessionId);
                sessionsForAccount.splice(sessionIndex);

                if (!sessionsForAccount.length) {
                    this._accounts.delete(accountName);
                }
            }
        });

        addedSessions.forEach(s => this.registerSession(s));
    }

    login(scopes: string[]): Promise<AuthenticationSession> {
        return this.proxy.$login(this.id, scopes);
    }

    async logout(sessionId: string): Promise<void> {
        await this.proxy.$logout(this.id, sessionId);
        this.messageService.info('Successfully signed out.');
    }

    dispose(): void {
    }
}

async function readAccountUsages(storageService: StorageService, providerId: string, accountName: string): Promise<AccountUsage[]> {
    const accountKey = `${providerId}-${accountName}-usages`;
    const storedUsages: string | undefined = await storageService.getData(accountKey);
    let usages: AccountUsage[] = [];
    if (storedUsages) {
        try {
            usages = JSON.parse(storedUsages);
        } catch (e) {
            // ignore
        }
    }

    return usages;
}

function removeAccountUsage(storageService: StorageService, providerId: string, accountName: string): void {
    const accountKey = `${providerId}-${accountName}-usages`;
    storageService.setData(accountKey, undefined);
}
