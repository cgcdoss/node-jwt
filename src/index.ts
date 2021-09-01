import cors from 'cors';
import dotenv from 'dotenv';
import express, { json, NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { uid } from 'uid';

class App {
  app = express();
  routes = express.Router();
  refreshTokens: { refreshToken: string, usuario: string }[] = [];

  constructor() {
    dotenv.config();

    this.app.set('env', {
      secret: process.env.SECRET
    });

    this.app.use(cors());
    this.app.use(json());

    this.carregaRotasAuth();
    this.carregaRotasExemplo();

    this.app.use('/api', this.routes);
  }

  private carregaRotasAuth(): void {
    this.routes.post('/login', (req, res) => {
      if ((req.body.user === 'cgc' || req.body.user === 'cgcdoss') && req.body.password === '123') {
        const id = 1; // Viria do banco
        const token = jwt.sign({ id, usuario: req.body.user }, this.app.get('env').secret, {
          expiresIn: 300,
          // notBefore: '7d', // define a partir de qual data aquele token se torna válido
        });

        let refreshToken = uid(256);
        this.refreshTokens.push({ refreshToken, usuario: req.body.user });

        res.json({ auth: true, token, refreshToken });
      } else {
        res.status(400).json({ msg: 'Login inválido' });
      }
    });

    this.routes.post('/logout', (req, res) => {
      const username = req.body.user;
      const refreshToRemove = this.refreshTokens.find(r => r.usuario === username);
      if (refreshToRemove)
        this.refreshTokens.splice(this.refreshTokens.indexOf(refreshToRemove), 1);

      res.json({ auth: false, token: null });
    });

    this.routes.post('/token', (req, res) => {
      const username = req.body.user;
      const refreshToken = req.body.refreshToken;

      if (this.refreshTokens.find(t => t.refreshToken === refreshToken && t.usuario === username)) {
        const id = 1;
        const token = jwt.sign({ id, usuario: username }, this.app.get('env').secret, {
          expiresIn: 300
        });

        res.json({ auth: true, token });
      }
    });

    this.routes.post('/tokencomjwt', (req, res) => {
      const username = req.body.user;
      const refreshToken = req.body.refreshToken;

      if (refreshToken) {
        jwt.verify(refreshToken, 'outrosegredo', (err: any, decoded: any) => {
          if (err) {
            res.status(400).json({ auth: false, msg: `Token inválido: ${err.message}`, data: err });
          } else {
            const id = 1;
            const token = jwt.sign({ id, usuario: username }, this.app.get('env').secret, {
              expiresIn: 300
            });

            res.json({ auth: true, token });
          }
        });
      } else {
        res.status(401).json({ auth: false, msg: 'Nenhum token informado no header' });
      }
    });
  }

  verificaJWTAsincrono(req: Request, res: Response, next: NextFunction): void {
    const token = req.headers['x-access-token'] as string;
    if (token) {
      jwt.verify(token, process.env.SECRET as string, (err: any, decoded: any) => {
        if (err) {
          res.status(400).json({ auth: false, msg: `Token inválido: ${err.message}`, data: err });
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
    const token = req.headers['x-access-token'] as string;
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.SECRET as string) as jwt.JwtPayload;
        (req as any).userId = decoded.id;
        next();
      } catch (error: any) {
        res.status(400).json({ auth: false, msg: `Token inválido: ${error.message}`, data: error });
      }
    } else {
      res.status(401).json({ auth: false, msg: 'Nenhum token informado no header' });
    }
  }

  private carregaRotasExemplo(): void {
    this.routes.get('/clientes', this.verificaJWTAsincrono, (req, res) => { // desse jeito não posso chamar propriedades dessa classe, pois elas não vão existir no momento que o verifyJWT for chamado
      res.json([{ nome: 'cliente1' }]);
    });

    this.routes.get(
      '/funcionarios',
      (req, res, next) => this.verificaJWTSincrono(req, res, next), // desse jeito posso chamar propriedade e métodos dessa class, tipo this.app.get(...)
      (req, res) => {
        res.json([{ nome: 'funci1' }]);
      }
    );
  }
}

new App().app.listen(3333);
