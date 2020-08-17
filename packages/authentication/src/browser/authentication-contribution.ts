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

import { injectable, inject } from 'inversify';
import {
    Command,
    CommandContribution, CommandRegistry,
    MAIN_MENU_BAR,
    MenuContribution,
    MenuModelRegistry
} from '@theia/core/lib/common';
import { AuthenticationService } from './authentication-service';

const AuthenticationCommand: Command = {
    id: 'authentication-command',
    label: 'Authentication Command'
};

@injectable()
export class AuthenticationContribution implements MenuContribution, CommandContribution {

    @inject(AuthenticationService) protected readonly service: AuthenticationService;

    registerCommands(commands: CommandRegistry): void {
        this.service.onDidRegisterAuthenticationProvider(providerId => {
            commands.registerCommand(AuthenticationCommand, handler);
        });
        const handler = {
            execute: () => {
                // this.service.manageTrustedExtensionsForAccount('github', 'vinokurig');
            },
            isEnabled(): boolean {
                return true;
            }
        };
        commands.registerCommand(AuthenticationCommand, handler);
    }

    registerMenus(menus: MenuModelRegistry): void {
        const subMenuPath = [...MAIN_MENU_BAR, 'authentication-menu'];
        menus.registerSubmenu(subMenuPath, 'Authentication', {
            order: '3' // that should put the menu right next to the File menu
        });
        menus.registerMenuAction(subMenuPath, {
            commandId: AuthenticationCommand.id
        });
    }
}
