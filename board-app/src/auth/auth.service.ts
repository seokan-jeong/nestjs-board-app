import { ConflictException, Injectable, InternalServerErrorException, UnauthorizedException } from "@nestjs/common";
import { Repository } from "typeorm";
import { User } from "./user.entity";
import { AuthCredentialDto } from "./dto/auth-credential.dto";
import { InjectRepository } from "@nestjs/typeorm";
import * as bcrypt from 'bcryptjs';


@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) {
  }

  async signUp(authCredentialDto: AuthCredentialDto): Promise<void> {
    const { username, password } = authCredentialDto;

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = this.userRepository.create({ username: username, password: hashedPassword });

    try {
      await this.userRepository.save(user);
    }catch(error) {
      if(error.code === '23505'){
        throw new ConflictException('Existing username')
      }else {
        throw new InternalServerErrorException()
      }
    }
  }

  async signIn(authCredentialDto: AuthCredentialDto): Promise<string> {
    const {username, password} = authCredentialDto;
    const user = await this.userRepository.findOne({
      where: {
        username
      }
    })

    if(user && (await bcrypt.compare(password, user.password))){
      return "login success"
    }

    throw new UnauthorizedException("login failed")
  }
}