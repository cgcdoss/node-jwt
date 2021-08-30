import dotenv from 'dotenv';
import express, { json, NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

class App {
  app = express();

  constructor() {
    dotenv.config();

    this.app.set('env', {
      secret: process.env.SECRET
    });

    this.app.use(json());

    this.app.post('/login', (req, res) => {
      if (req.body.user === 'cgcdoss' && req.body.password === '123') {
        const id = 1; // Viria do banco
        const token = jwt.sign({ id, usuario: 'Lester' }, this.app.get('env').secret, {
          expiresIn: 300,
          // notBefore: '7d', // define a partir de qual data aquele token se torna válido
        });

        res.json({ auth: true, token });
      } else {
        res.status(500).json({ msg: 'Login inválido' });
      }
    });

    this.app.post('/logout', (req, res) => res.json({ auth: false, token: null }));

    this.app.get('/clientes', this.verificaJWTAsincrono, (req, res) => { // desse jeito não posso chamar propriedades dessa classe, pois elas não vão existir no momento que o verifyJWT for chamado
      res.json([{ nome: 'cliente1' }]);
    });

    this.app.get(
      '/funcionarios',
      (req, res, next) => this.verificaJWTSincrono(req, res, next), // desse jeito posso chamar propriedade e métodos dessa class, tipo this.app.get(...)
      (req, res) => {
        res.json([{ nome: 'funci1' }]);
      }
    );

  }

  verificaJWTAsincrono(req: Request, res: Response, next: NextFunction): void {
    const token = req.headers['x-acess-token'] as string;
    if (token) {
      jwt.verify(token, process.env.SECRET as string, (err: any, decoded: any) => {
        if (err) {
          res.status(500).json({ auth: false, msg: `Token inválido: ${err.message}`, data: err });
        } else {
          (req as any).userId = decoded.id;
          next();
        }
      });
    } else {
      res.status(401).json({ auth: false, msg: 'Nenhum token informado no header' });
    }
  }

  verificaJWTSincrono(req: Request, res: Response, next: NextFunction): void {
    const token = req.headers['x-acess-token'] as string;
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.SECRET as string) as jwt.JwtPayload;
        (req as any).userId = decoded.id;
        next();
      } catch (error: any) {
        res.status(500).json({ auth: false, msg: `Token inválido: ${error.message}`, data: error });
      }
    } else {
      res.status(401).json({ auth: false, msg: 'Nenhum token informado no header' });
    }
  }
}

new App().app.listen(3333);
