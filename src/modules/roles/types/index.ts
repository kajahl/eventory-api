export enum Role {
    Admin = 'admin',
    EventCreator = 'event_creator',
    User = 'user',
}

export const RolePriority: Record<Role, number> = {
    [Role.Admin]: 1000,
    [Role.EventCreator]: 100,
    [Role.User]: 1, 
};

export enum Scope {
    // Users
    UsersRead = 'users:read',
    UsersReadMe = 'users:read:me',

    // Roles
    RolesRead = 'roles:read',
    RolesReadMe = 'roles:read:me',
    RolesReadUsers = 'role:read:users',
    RolesManage = 'role:manage',

    // Events
    EventsRead = 'events:read',
    EventsReadMe = 'events:read:me',
    EventsCreate = 'events:create',
    EventsUpdate = 'events:update',
    EventsDelete = 'events:delete',
    EventsUsersManage = 'events:users:manage',
    EventsUsersManageMe = 'events:users:manage:me',
}

function allScopes() : Scope[] {
    return Object.values(Scope).filter((scope) => typeof scope === 'string') as Scope[];
}

function getEventCreatorScopes(): Scope[] {
    return [
        Scope.EventsRead,
        Scope.EventsReadMe,
        Scope.EventsCreate,
        Scope.EventsUpdate,
        Scope.EventsDelete,
        Scope.EventsUsersManage,
        Scope.EventsUsersManageMe,
        ...getUserScopes(),
    ];
}

function getUserScopes(): Scope[] {
    return [
        Scope.UsersRead,
        Scope.UsersReadMe,
        Scope.EventsRead,
        Scope.EventsReadMe,
    ];
}

export const RoleScopeMapping: Record<Role, Scope[]> = {
    [Role.Admin]: allScopes(),
    [Role.EventCreator]: getEventCreatorScopes(),
    [Role.User]: getUserScopes(),
}

export function getRoleScopeMapping(): Record<Role, Scope[]> {
    return RoleScopeMapping;
}