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

import { injectable } from 'inversify';
import { Emitter, Event } from '@theia/core/lib/common/event';
import { Disposable } from '@theia/core/lib/common/disposable';
import { StorageService } from '@theia/core/lib/browser/storage-service';

export interface AuthenticationSession {
    id: string;
    accessToken: string;
    account: {
        displayName: string;
        id: string;
    }
    scopes: string[];
}

export interface AuthenticationSessionsChangeEvent {
    added: string[];
    removed: string[];
    changed: string[];
}

export interface AuthenticationProvider extends Disposable {
    id: string;

    supportsMultipleAccounts: boolean;

    displayName: string;

    initialize(): Promise<void>;

    hasSessions(): boolean;

    signOut(accountName: string): Promise<void>;

    getSessions(): Promise<ReadonlyArray<AuthenticationSession>>;

    updateSessionItems(event: AuthenticationSessionsChangeEvent): Promise<void>;

    login(scopes: string[]): Promise<AuthenticationSession>;

    logout(sessionId: string): Promise<void>;
}
export const AuthenticationService = Symbol('AuthenticationService');

export interface AuthenticationService {
    readonly _serviceBrand: undefined;

    isAuthenticationProviderRegistered(id: string): boolean;
    getProviderIds(): string[];
    registerAuthenticationProvider(id: string, provider: AuthenticationProvider): void;
    unregisterAuthenticationProvider(id: string): void;
    requestNewSession(id: string, scopes: string[], extensionId: string, extensionName: string): void;
    sessionsUpdate(providerId: string, event: AuthenticationSessionsChangeEvent): void;

    readonly onDidRegisterAuthenticationProvider: Event<string>;
    readonly onDidUnregisterAuthenticationProvider: Event<string>;

    readonly onDidChangeSessions: Event<{ providerId: string, event: AuthenticationSessionsChangeEvent }>;
    getSessions(providerId: string): Promise<ReadonlyArray<AuthenticationSession>>;
    getDisplayName(providerId: string): string;
    supportsMultipleAccounts(providerId: string): boolean;
    login(providerId: string, scopes: string[]): Promise<AuthenticationSession>;
    logout(providerId: string, sessionId: string): Promise<void>;

    signOutOfAccount(providerId: string, accountName: string): Promise<void>;
}

export interface SessionRequest {
    disposables: Disposable[];
    requestingExtensionIds: string[];
}

export interface SessionRequestInfo {
    [scopes: string]: SessionRequest;
}

@injectable()
export class AuthenticationServiceImpl implements Disposable, AuthenticationService {
    declare readonly _serviceBrand: undefined;
    private _placeholderMenuItem: Disposable | undefined;
    private _noAccountsMenuItem: Disposable | undefined;
    private _signInRequestItems = new Map<string, SessionRequestInfo>();
    private _badgeDisposable: Disposable | undefined;

    private _authenticationProviders: Map<string, AuthenticationProvider> = new Map<string, AuthenticationProvider>();

    private _onDidRegisterAuthenticationProvider: Emitter<string> = new Emitter<string>();
    readonly onDidRegisterAuthenticationProvider: Event<string> = this._onDidRegisterAuthenticationProvider.event;

    private _onDidUnregisterAuthenticationProvider: Emitter<string> = new Emitter<string>();
    readonly onDidUnregisterAuthenticationProvider: Event<string> = this._onDidUnregisterAuthenticationProvider.event;

    private _onDidChangeSessions: Emitter<{ providerId: string, event: AuthenticationSessionsChangeEvent }> =
        new Emitter<{ providerId: string, event: AuthenticationSessionsChangeEvent }>();
    readonly onDidChangeSessions: Event<{ providerId: string, event: AuthenticationSessionsChangeEvent }> = this._onDidChangeSessions.event;

    // constructor(@IActivityService private readonly activityService: IActivityService) {
    constructor() {
        // this._placeholderMenuItem = MenuRegistry.appendMenuItem(MenuId.AccountsContext, {
        //     command: {
        //         id: 'noAuthenticationProviders',
        //         title: nls.localize('loading', "Loading..."),
        //         precondition: ContextKeyExpr.false()
        //     },
        // });
    }

    getProviderIds(): string[] {
        const providerIds: string[] = [];
        this._authenticationProviders.forEach(provider => {
            providerIds.push(provider.id);
        });
        return providerIds;
    }

    isAuthenticationProviderRegistered(id: string): boolean {
        return this._authenticationProviders.has(id);
    }

    private updateAccountsMenuItem(): void {
        let hasSession = false;
        this._authenticationProviders.forEach(async provider => {
            hasSession = hasSession || provider.hasSessions();
        });

        if (hasSession && this._noAccountsMenuItem) {
            this._noAccountsMenuItem.dispose();
            this._noAccountsMenuItem = undefined;
        }

        if (!hasSession && !this._noAccountsMenuItem) {
            // this._noAccountsMenuItem = MenuRegistry.appendMenuItem(MenuId.AccountsContext, {
            //     group: '0_accounts',
            //     command: {
            //         id: 'noAccounts',
            //         title: nls.localize('noAccounts', "You are not signed in to any accounts"),
            //         precondition: ContextKeyExpr.false()
            //     },
            // });
        }
    }

    registerAuthenticationProvider(id: string, authenticationProvider: AuthenticationProvider): void {
        this._authenticationProviders.set(id, authenticationProvider);
        this._onDidRegisterAuthenticationProvider.fire(id);

        if (this._placeholderMenuItem) {
            this._placeholderMenuItem.dispose();
            this._placeholderMenuItem = undefined;
        }

        this.updateAccountsMenuItem();
    }

    unregisterAuthenticationProvider(id: string): void {
        const provider = this._authenticationProviders.get(id);
        if (provider) {
            provider.dispose();
            this._authenticationProviders.delete(id);
            this._onDidUnregisterAuthenticationProvider.fire(id);
            this.updateAccountsMenuItem();
        }

        if (!this._authenticationProviders.size) {
            // this._placeholderMenuItem = MenuRegistry.appendMenuItem(MenuId.AccountsContext, {
            //     command: {
            //         id: 'noAuthenticationProviders',
            //         title: nls.localize('loading', "Loading..."),
            //         precondition: ContextKeyExpr.false()
            //     },
            // });
        }
    }

    async sessionsUpdate(id: string, event: AuthenticationSessionsChangeEvent): Promise<void> {
        this._onDidChangeSessions.fire({ providerId: id, event: event });
        const provider = this._authenticationProviders.get(id);
        if (provider) {
            await provider.updateSessionItems(event);
            this.updateAccountsMenuItem();

            if (event.added) {
                await this.updateNewSessionRequests(provider);
            }
        }
    }

    private async updateNewSessionRequests(provider: AuthenticationProvider): Promise<void> {
        const existingRequestsForProvider = this._signInRequestItems.get(provider.id);
        if (!existingRequestsForProvider) {
            return;
        }

        const sessions = await provider.getSessions();
        let changed = false;

        Object.keys(existingRequestsForProvider).forEach(requestedScopes => {
            if (sessions.some(session => session.scopes.sort().join('') === requestedScopes)) {
                // Request has been completed
                changed = true;
                const sessionRequest = existingRequestsForProvider[requestedScopes];
                if (sessionRequest) {
                    sessionRequest.disposables.forEach(item => item.dispose());
                }

                delete existingRequestsForProvider[requestedScopes];
                if (Object.keys(existingRequestsForProvider).length === 0) {
                    this._signInRequestItems.delete(provider.id);
                } else {
                    this._signInRequestItems.set(provider.id, existingRequestsForProvider);
                }
            }
        });

        if (changed) {
            if (this._signInRequestItems.size === 0) {
                if (this._badgeDisposable) {
                    this._badgeDisposable.dispose();
                }
                this._badgeDisposable = undefined;
            } else {
                // let numberOfRequests = 0;
                // this._signInRequestItems.forEach(providerRequests => {
                //     Object.keys(providerRequests).forEach(request => {
                //         numberOfRequests += providerRequests[request].requestingExtensionIds.length;
                //     });
                // });

                // const badge = new NumberBadge(numberOfRequests, () => nls.localize('sign in', "Sign in requested"));
                // this._badgeDisposable = this.activityService.showAccountsActivity({ badge });
            }
        }
    }

    requestNewSession(providerId: string, scopes: string[], extensionId: string, extensionName: string): void {
        const provider = this._authenticationProviders.get(providerId);
        if (provider) {
            const providerRequests = this._signInRequestItems.get(providerId);
            const scopesList = scopes.sort().join('');
            const extensionHasExistingRequest = providerRequests
                && providerRequests[scopesList]
                && providerRequests[scopesList].requestingExtensionIds.indexOf(extensionId) > -1;

            if (extensionHasExistingRequest) {
                return;
            }

            // const menuItem = MenuRegistry.appendMenuItem(MenuId.AccountsContext, {
            //     group: '2_signInRequests',
            //     command: {
            //         id: `${extensionId}signIn`,
            //         title: nls.localize(
            //             {
            //                 key: 'signInRequest',
            //                 comment: ['The placeholder {0} will be replaced with an extension name. (1) is to indicate that this menu item contributes to a badge count.']
            //             },
            //             "Sign in to use {0} (1)",
            //             extensionName)
            //     }
            // });

            // const signInCommand = CommandsRegistry.registerCommand({
            //     id: `${extensionId}signIn`,
            //     handler: async (accessor) => {
            //         const authenticationService = accessor.get(IAuthenticationService);
            //         const storageService = accessor.get(IStorageService);
            //         const session = await authenticationService.login(providerId, scopes);
            //
            //         // Add extension to allow list since user explicitly signed in on behalf of it
            //         const allowList = readAllowedExtensions(storageService, providerId, session.account.displayName);
            //         if (!allowList.find(allowed => allowed.id === extensionId)) {
            //             allowList.push({ id: extensionId, name: extensionName });
            //             storageService.store(`${providerId}-${session.account.displayName}`, JSON.stringify(allowList), StorageScope.GLOBAL);
            //         }
            //
            //         // And also set it as the preferred account for the extension
            //         storageService.store(`${extensionName}-${providerId}`, session.id, StorageScope.GLOBAL);
            //     }
            // });

            // if (providerRequests) {
            //     const existingRequest = providerRequests[scopesList] || { disposables: [], requestingExtensionIds: [] };
            //
            //     providerRequests[scopesList] = {
            //         disposables: [...existingRequest.disposables, menuItem, signInCommand],
            //         requestingExtensionIds: [...existingRequest.requestingExtensionIds, extensionId]
            //     };
            //     this._signInRequestItems.set(providerId, providerRequests);
            // } else {
            //     this._signInRequestItems.set(providerId, {
            //         [scopesList]: {
            //             disposables: [menuItem, signInCommand],
            //             requestingExtensionIds: [extensionId]
            //         }
            //     });
            // }
            //
            // let numberOfRequests = 0;
            // this._signInRequestItems.forEach(providerRequests => {
            //     Object.keys(providerRequests).forEach(request => {
            //         numberOfRequests += providerRequests[request].requestingExtensionIds.length;
            //     });
            // });
            //
            // const badge = new NumberBadge(numberOfRequests, () => nls.localize('sign in', "Sign in requested"));
            // this._badgeDisposable = this.activityService.showAccountsActivity({ badge });
        }
    }
    getDisplayName(id: string): string {
        const authProvider = this._authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.displayName;
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    supportsMultipleAccounts(id: string): boolean {
        const authProvider = this._authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.supportsMultipleAccounts;
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async getSessions(id: string): Promise<ReadonlyArray<AuthenticationSession>> {
        const authProvider = this._authenticationProviders.get(id);
        if (authProvider) {
            return await authProvider.getSessions();
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async login(id: string, scopes: string[]): Promise<AuthenticationSession> {
        const authProvider = this._authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.login(scopes);
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async logout(id: string, sessionId: string): Promise<void> {
        const authProvider = this._authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.logout(sessionId);
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    async signOutOfAccount(id: string, accountName: string): Promise<void> {
        const authProvider = this._authenticationProviders.get(id);
        if (authProvider) {
            return authProvider.signOut(accountName);
        } else {
            throw new Error(`No authentication provider '${id}' is currently registered.`);
        }
    }

    dispose(): void {
    }
}

export interface AllowedExtension {
    id: string;
    name: string;
}

export async function readAllowedExtensions(storageService: StorageService, providerId: string, accountName: string): Promise<AllowedExtension[]> {
    let trustedExtensions: AllowedExtension[] = [];
    try {
        const trustedExtensionSrc: string | undefined = await storageService.getData(`${providerId}-${accountName}`);
        if (trustedExtensionSrc) {
            trustedExtensions = JSON.parse(trustedExtensionSrc);
        }
    } catch (err) { }

    return trustedExtensions;
}
