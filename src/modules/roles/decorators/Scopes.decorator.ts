import { SetMetadata } from '@nestjs/common';
import { Scope } from '../types/';

export const Scopes = (...scopes: Scope[]) => SetMetadata('scopes', scopes);