import { NextFunction, Request } from 'express';
import { verify } from 'jsonwebtoken';

import { AppError } from '../errors/AppErrors';
import { UsersRepository } from '../modules/accounts/repositories/implementations/UsersRepository';

interface IPayLoad {
  user_id: string;
}
export async function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction,
) {
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    throw new AppError('Token missing!', 401);
  }

  const [, token] = authHeader.split(' ');

  try {
    const { user_id } = verify(
      token,
      '009b22f947e3d5530b521896e532ab6c',
    ) as IPayLoad;

    const usersRepository = new UsersRepository();

    const user = usersRepository.findById(user_id);

    if (!user) {
      throw new AppError('User does not exists!', 401);
    }

    next();
  } catch (error) {
    throw new AppError('Invalid token!', 401);
  }
}
