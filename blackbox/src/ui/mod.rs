use std::sync::Arc;

use color_eyre::Result;
use iced::{
    widget::{container, row, text, Space},
    Application, Command, Executor, Length, Settings, Theme,
};
use tokio::sync::{Mutex, Notify};

use crate::types::ProcessingData;

struct CurrentExecutor {}

impl Executor for CurrentExecutor {
    fn new() -> std::result::Result<Self, futures::io::Error>
    where
        Self: Sized,
    {
        Ok(Self {})
    }

    fn spawn(&self, future: impl futures::Future<Output = ()> + Send + 'static) {
        tokio::runtime::Handle::current().spawn(future);
    }
}

pub fn run(done: Arc<tokio::sync::Notify>, shared_state: Arc<Mutex<Option<ProcessingData>>>) -> Result<()> {
    App::run(Settings {
        flags: Flags { done },
        id: None,
        window: Default::default(),
        default_font: Default::default(),
        default_text_size: 16.0,
        antialiasing: false,
        exit_on_close_request: true,
    })?;
    Ok(())
}

#[derive(Debug)]
enum State {
    Processing,
    Finished,
}

#[derive(Debug)]
struct App {
    state: State,
}

#[derive(Debug)]
struct Flags {
    done: Arc<Notify>,
}

#[derive(Debug)]
enum Message {
    Done(()),
}

impl Application for App {
    type Executor = CurrentExecutor;

    type Message = Message;

    type Theme = Theme;

    type Flags = Flags;

    fn new(flags: Self::Flags) -> (Self, iced::Command<Self::Message>) {
        (
            Self {
                state: State::Processing,
            },
            Command::perform(async move { flags.done.notified().await }, Message::Done),
        )
    }

    fn title(&self) -> String {
        String::from("Blackbox")
    }

    fn update(&mut self, message: Self::Message) -> iced::Command<Self::Message> {
        match message {
            Message::Done(()) => {
                self.state = State::Finished;
                Command::none()
            }
        }
    }

    fn view(&self) -> iced::Element<'_, Self::Message, iced::Renderer<Self::Theme>> {
        // TODO: add the actual information in here
        let text: iced::Element<_> = match self.state {
            State::Processing => row!(
                Space::new(Length::FillPortion(3), 0),
                text("Processing, please wait. If you need to interact with the process, use the command line where Blackbox was started.").size(20).width(Length::FillPortion(3)),
                Space::new(Length::FillPortion(3), 0),
            ).into(),
            State::Finished => text("Done!").size(50).into(),
        };
        container(text)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}
