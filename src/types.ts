export type CreateSessionDTO = {
  email: string;
  password: string;
}

export type UserData = {
  password?: string;
  name: string;
  permissions: string[];
  roles: string[];
  createdAt: Date;
}

export type UsersStore = Map<string, UserData>

export type RefreshTokensStore = Map<string, string[]>

export type DecodedToken = {
  sub: string;
}