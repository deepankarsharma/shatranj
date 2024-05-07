use std::io;
use pgn_reader::{Visitor, Skip, BufferedReader, SanPlus};

struct MoveCounter {
    moves: usize,
}

impl MoveCounter {
    fn new() -> MoveCounter {
        MoveCounter { moves: 0 }
    }
}

impl Visitor for MoveCounter {
    type Result = usize;

    fn begin_game(&mut self) {
        self.moves = 0;
    }

    fn san(&mut self, _san_plus: SanPlus) {
        self.moves += 1;
    }

    fn begin_variation(&mut self) -> Skip {
        Skip(true) // stay in the mainline
    }

    fn end_game(&mut self) -> Self::Result {
        self.moves
    }
}

fn main() -> io::Result<()> {
    let pgn = b"1. e4 e5 2. Nf3 (2. f4)
                { game paused due to bad weather }
                2... Nf6 *";

    let mut reader = BufferedReader::new_cursor(&pgn[..]);

    let mut counter = MoveCounter::new();
    let moves = reader.read_game(&mut counter)?;

    assert_eq!(moves, Some(4));
    Ok(())
}