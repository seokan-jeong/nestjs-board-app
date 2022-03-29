import { Injectable, NotFoundException } from "@nestjs/common";
import { BoardStatus } from './board-status.enum';
import { v1 as uuid } from 'uuid';
import { CreateBoardDto } from './dto/create-board.dto';
import { InjectRepository } from "@nestjs/typeorm";
import { Board } from "./board.entity";
import { Repository } from "typeorm";

@Injectable()
export class BoardsService {
  constructor(
    @InjectRepository(Board)
    private boardRepository: Repository<Board>,
  ) {}

  async createBoard(createBoardDto: CreateBoardDto): Promise<Board>{
    const {title, description} = createBoardDto;

    const board = this.boardRepository.create({
      title: title,
      description: description,
      status: BoardStatus.PUBLIC
    })

    await this.boardRepository.save(board);
    return board;
  }

  async getAllBoards(): Promise<Board[]> {
    return await this.boardRepository.find();
  }

  async getBoardById(id: number): Promise<Board> {
    const found = await this.boardRepository.findOne({
      where: {
        id: id,
      },
    })

    if(!found){
      throw new NotFoundException('Can\'t find Board with id ' + id)
    }

    return found;
  }

  async deleteBoard(id: number): Promise<void> {
    const result = await this.boardRepository.delete(id);

    if(result.affected === 0){
      throw new NotFoundException('Can\'t find board with id ' + id)
    }

    console.log('result', result);
  }

  async updateBoardStatus(id: number, status: BoardStatus): Promise<Board> {
    const board = await this.getBoardById(id);

    board.status = status;

    await this.boardRepository.save(board);
    return board;
  }
}
