use std::sync::Arc;

use color_eyre::Result;
use iced::{
    theme::{Button, Container},
    widget::{button, column, container, row, scrollable, text, Row, Space},
    Application, Color, Command, Executor, Length, Settings, Theme,
};
use tokio::sync::{Mutex, Notify};

use crate::types::{
    AccessType, Connection, FileAccess, FileSummary, NetworkSummary, ProcessSummary,
    ProcessingData, SpawnEvent,
};

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

pub fn run(
    done: Arc<tokio::sync::Notify>,
    shared_state: Arc<Mutex<Option<ProcessingData>>>,
) -> Result<()> {
    App::run(Settings {
        flags: Flags { done, shared_state },
        id: None,
        window: Default::default(),
        default_font: Default::default(),
        default_text_size: 16.0,
        antialiasing: false,
        exit_on_close_request: true,
    })?;
    Ok(())
}

#[derive(Debug, Clone)]
enum State {
    Processing,
    OnTab(Tab),
}

#[derive(Debug)]
struct App {
    state: State,
    data: ProcessingData,
}

#[derive(Debug)]
struct Flags {
    done: Arc<Notify>,
    shared_state: Arc<Mutex<Option<ProcessingData>>>,
}

#[derive(Debug, Clone)]
enum Tab {
    Summary,
    File,
    Network,
    Process,
}

#[derive(Debug, Clone)]
enum Message {
    Done(Box<ProcessingData>),
    SwitchTab(Tab),
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
                data: ProcessingData::default(),
            },
            Command::perform(
                async move {
                    flags.done.notified().await;
                    Box::new(flags.shared_state.lock().await.take().unwrap())
                },
                Message::Done,
            ),
        )
    }

    fn title(&self) -> String {
        String::from("Blackbox")
    }

    fn update(&mut self, message: Self::Message) -> iced::Command<Self::Message> {
        match message {
            Message::Done(processing_data) => {
                self.state = State::OnTab(Tab::Summary);
                self.data = *processing_data;
                Command::none()
            }
            Message::SwitchTab(tab) => {
                self.state = State::OnTab(tab);
                Command::none()
            }
        }
    }

    fn view(&self) -> iced::Element<'_, Self::Message, iced::Renderer<Self::Theme>> {
        let tabs = column!(
            button("Summary").on_press(Message::SwitchTab(Tab::Summary)),
            button("Files").on_press(Message::SwitchTab(Tab::File)),
            button("Network").on_press(Message::SwitchTab(Tab::Network)),
            button("Processes").on_press(Message::SwitchTab(Tab::Process)),
        );
        // TODO: add the actual information in here
        let main_view: iced::Element<_> = match &self.state {
            State::Processing => row!(
                Space::new(Length::FillPortion(3), 0),
                text("Processing, please wait. If you need to interact with the process, use the command line where Blackbox was started.").size(20).width(Length::FillPortion(3)),
                Space::new(Length::FillPortion(3), 0),
            ).into(),
            State::OnTab(tab) => row!(
                tabs,
                match tab {
                    Tab::Summary => Self::summary_view(&self.data),
                    Tab::File => Self::file_view(&self.data),
                    Tab::Network => Self::network_view(&self.data),
                    Tab::Process => Self::process_view(&self.data),
                },
            ).into()
        };
        container(main_view)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}

type Element<'a> = iced::Element<
    'a,
    <App as iced::Application>::Message,
    iced::Renderer<<App as iced::Application>::Theme>,
>;

impl App {
    fn summary_view(data: &ProcessingData) -> Element<'_> {
        let alerts = data
            .alerts
            .iter()
            .map(|alert| {
                button(text(&alert.message))
                    .style(match alert.severity {
                        0 => Button::Destructive,
                        1 => Button::Secondary,
                        2 => Button::Positive,
                        _ => Button::Primary,
                    })
                    .into()
            })
            .collect::<Vec<iced::Element<_>>>();
        let alerts = scrollable(column(alerts)).height(100).width(Length::Fill);

        let file_summary = row![
            container(text("File access:"))
                .padding(10)
                .width(Length::FillPortion(1)),
            Self::create_file_summary(&data.file_summary),
        ];

        let network_summary = row![
            container(text("Network:")).padding(10),
            Self::create_network_summary(&data.network_summary)
        ];

        let process_summary = row![
            container(text("Processes:")).padding(10),
            Self::create_process_summary(&data.process_summary)
        ];

        let main_view = column!(
            text("Alerts:"),
            alerts,
            file_summary,
            network_summary,
            process_summary
        );
        scrollable(main_view)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn file_view(data: &ProcessingData) -> Element<'_> {
        column![
            text("Summary:"),
            Self::create_file_summary(&data.file_summary),
            text("File Access Details:"),
            scrollable(column(
                data.file_events
                    .iter()
                    .map(Self::create_file_event)
                    .collect()
            )),
        ]
        .into()
    }

    fn network_view(data: &ProcessingData) -> Element<'_> {
        column![
            text("Summary:"),
            Self::create_network_summary(&data.network_summary),
            text("Connection Details:"),
            scrollable(column(
                data.network_events
                    .iter()
                    .map(Self::create_connection)
                    .collect()
            )),
        ]
        .into()
    }

    fn process_view(data: &ProcessingData) -> Element<'_> {
        column![
            text("Summary:"),
            Self::create_process_summary(&data.process_summary),
            text("Process Details:"),
            scrollable(column(
                data.process_events
                    .iter()
                    .map(Self::create_spawn_event)
                    .collect()
            )),
        ]
        .into()
    }

    fn create_access_mark(access: AccessType) -> Element<'static> {
        let mut boxes = vec![];
        if access.read {
            boxes.push(
                container(text("R").style(Color::from_rgba(0.9, 0.1, 0.0, 0.7)))
                    .padding(5)
                    .into(),
            );
        }
        if access.write {
            boxes.push(
                container(text("W").style(Color::from_rgba(0.1, 0.9, 0.0, 0.7)))
                    .padding(5)
                    .into(),
            );
        }
        if access.execute {
            boxes.push(
                container(text("X").style(Color::from_rgba(0.1, 0.1, 0.9, 0.7)))
                    .padding(5)
                    .into(),
            );
        }
        container(row(boxes)).into()
    }

    fn create_file_summary(file_summary: &FileSummary) -> Element<'static> {
        column![
            row![
                container(column![
                    row![
                        text("Standard I/O:"),
                        Space::with_width(Length::Fill),
                        Self::create_access_mark(file_summary.behavior.stdio),
                    ],
                    row![
                        text("Current Directory:"),
                        Space::with_width(Length::Fill),
                        Self::create_access_mark(file_summary.behavior.current_dir),
                    ],
                    row![
                        text("Home Directory:"),
                        Space::with_width(Length::Fill),
                        Self::create_access_mark(file_summary.behavior.home_dir),
                    ],
                    row![
                        text("System Files:"),
                        Space::with_width(Length::Fill),
                        Self::create_access_mark(file_summary.behavior.system),
                    ],
                    row![
                        text("Runtime Directories:"),
                        Space::with_width(Length::Fill),
                        Self::create_access_mark(file_summary.behavior.runtime),
                    ],
                ])
                .padding(10)
                .width(Length::FillPortion(1))
                .style(Container::Box),
                container(column![
                    text(format!("Files Accessed: {}", file_summary.access_count)),
                    text(format!("Total Bytes Read: {}", file_summary.bytes_read)),
                    text(format!(
                        "Total Bytes Written: {}",
                        file_summary.bytes_written
                    )),
                ])
                .width(Length::FillPortion(1))
                .style(Container::Box),
            ],
            column(
                file_summary
                    .directories
                    .iter()
                    .map(|dir| text(dir.to_string_lossy()).into())
                    .collect()
            ),
        ]
        .width(Length::FillPortion(5))
        .into()
    }

    fn create_network_summary(network_summary: &NetworkSummary) -> Element<'static> {
        column![
            text(format!(
                "Total Connections: {}",
                network_summary.connection_count,
            )),
            row![
                column![
                    text("Domains:"),
                    scrollable(column(
                        network_summary
                            .domains
                            .iter()
                            .map(|domain| text(format!("{:?}", domain)).into())
                            .collect()
                    ))
                ],
                column![
                    text("Protocols:"),
                    scrollable(column(
                        network_summary
                            .protocols
                            .iter()
                            .map(|protocol| text(format!("{:?}", protocol)).into())
                            .collect()
                    ))
                ]
            ],
        ]
        .into()
    }

    fn create_process_summary(process_summary: &ProcessSummary) -> Element<'static> {
        column![
            text(format!(
                "Total Processes Spawned: {}",
                process_summary.processes_created,
            )),
            text(format!(
                "Most Common Spawn Type: {:?}",
                process_summary.most_common_spawn_type,
            )),
            row![
                text("Processes executed:"),
                scrollable(column(
                    process_summary
                        .programs
                        .iter()
                        .map(|program| text(program.to_string_lossy()).into())
                        .collect()
                )),
            ],
        ]
        .into()
    }

    fn create_file_event(access: &FileAccess) -> Element<'static> {
        let data_views = Row::new()
            .push(Self::create_hex_preview(&access.read_data))
            .push(Self::create_hex_preview(&access.write_data));
        column![
            row![
                container(text(access.file_descriptor)),
                text(
                    access
                        .file_name
                        .clone()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or("No file name".into())
                ),
                Self::create_access_mark(access.access_type),
            ],
            data_views,
        ]
        .into()
    }

    fn create_hex_preview(bytes: &[u8]) -> Element<'static> {
        let hex = column(
            bytes
                .chunks_exact(16)
                .map(|chunk| {
                    row(chunk
                        .iter()
                        .map(|b| container(text(format!("{:x}", b))).into())
                        .collect())
                    .into()
                })
                .collect(),
        );
        let string = column(
            bytes
                .chunks_exact(16)
                .map(|chunk| {
                    text(
                        chunk
                            .iter()
                            .map(|b| {
                                let c = char::from_u32(*b as u32).unwrap_or('\0');
                                if c.is_ascii_digit() || c.is_alphabetic() {
                                    c
                                } else {
                                    '.'
                                }
                            })
                            .collect::<String>(),
                    )
                    .into()
                })
                .collect(),
        );
        row!(hex, string).into()
    }

    fn create_connection(conn: &Connection) -> Element<'static> {
        column![
            text(format!("Duration: {}", conn.end_time - conn.start_time)),
            text(format!("Protocol: {:?}", conn.protocol)),
            text(format!("Domain: {:?}", conn.domain)),
        ]
        .into()
    }

    fn create_spawn_event(spawn: &SpawnEvent) -> Element<'static> {
        column![
            row![
                text(
                    spawn
                        .command
                        .clone()
                        .unwrap_or("No Command".into())
                        .to_string_lossy()
                ),
                text(format!("{} -> {}", spawn.parent_id, spawn.process_id))
            ],
            text(format!("Timestamp: {}", spawn.spawn_time)),
            text(format!("Spawn Type: {:?}", spawn.spawn_type)),
        ]
        .into()
    }
}
