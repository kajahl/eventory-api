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
    UsersUpdate = 'users:update',
    UsersUpdateMe = 'users:update:me',
    UsersDelete = 'users:delete',
    UsersDeleteMe = 'users:delete:me',

    // Roles
    RolesRead = 'roles:read',
    RolesReadMe = 'roles:read:me',
    RolesReadUsers = 'roles:read:users',
    RolesManage = 'roles:manage',

    // Events
    EventsRead = 'events:read',
    EventsReadMe = 'events:read:me',
    EventsCreate = 'events:create',
    EventsUpdate = 'events:update',
    EventsDelete = 'events:delete',
    EventsJoinStrategiesRead = 'events:join:strategies:read',
    EventsJoinStrategiesManage = 'events:join:strategies:manage',
    EventsUsersManage = 'events:users:manage',
    EventsUsersManageMe = 'events:users:manage:me',
    EventsEnable = 'events:enable',
    EventsDisable = 'events:disable',
    EventsJoin = 'events:join',
    EventsLeave = 'events:leave',
}

function allScopes() : Scope[] {
    return Object.values(Scope).filter((scope) => typeof scope === 'string') as Scope[];
}

function getEventCreatorScopes(): Scope[] {
    return [
        Scope.EventsRead,
        Scope.EventsCreate,
        Scope.EventsUpdate,
        Scope.EventsDelete,
        Scope.EventsUsersManage,
        Scope.EventsJoinStrategiesRead,
        Scope.EventsJoinStrategiesManage,
        Scope.EventsEnable,
        Scope.EventsDisable
    ];
}

function getUserScopes(): Scope[] {
    return [
        Scope.UsersReadMe,
        Scope.UsersUpdateMe,
        Scope.UsersDeleteMe,
        Scope.EventsRead,
        Scope.EventsReadMe,
        Scope.EventsUsersManageMe,
        Scope.EventsJoin,
        Scope.EventsLeave,
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