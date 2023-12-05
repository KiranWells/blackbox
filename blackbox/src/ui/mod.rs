use std::sync::Arc;

use color_eyre::Result;
use iced::{
    font::{self, Family, Weight},
    theme::Button,
    widget::{button, column, container, row, scrollable, svg, text, tooltip, Row, Space},
    Application, Command, Executor, Font, Length, Settings,
};
use tokio::sync::{Mutex, Semaphore};

use crate::types::{
    AccessType, Connection, FileAccess, FileSummary, NetworkSummary, ProcessSummary,
    ProcessingData, SpawnEvent,
};

mod theme;

use theme::{ContainerType, Theme};

use self::theme::OFF_BLACK;

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
    done: Arc<tokio::sync::Semaphore>,
    shared_state: Arc<Mutex<Option<ProcessingData>>>,
) -> Result<()> {
    App::run(Settings {
        flags: Flags { done, shared_state },
        id: Some("Blackbox".to_string()),
        window: Default::default(),
        default_font: {
            Font {
                family: Family::Name("Raleway"),
                weight: Weight::Medium,
                ..Font::DEFAULT
            }
        },
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
    done: Arc<Semaphore>,
    shared_state: Arc<Mutex<Option<ProcessingData>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Summary,
    File,
    Network,
    Process,
}

#[derive(Debug, Clone)]
enum Message {
    Done(Box<ProcessingData>),
    FontLoaded(Result<(), font::Error>),
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
            Command::batch(vec![
                font::load(
                    include_bytes!("../../resources/Raleway-VariableFont_wght.ttf").as_slice(),
                )
                .map(Message::FontLoaded),
                Command::perform(
                    async move {
                        // this is being used as a notifier, because the real notifier does not
                        // remember it there was a notification sent with no waiter
                        let _ = flags.done.acquire().await.unwrap();
                        Box::new(flags.shared_state.lock().await.take().unwrap())
                    },
                    Message::Done,
                ),
            ]),
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
            Message::FontLoaded(r) => {
                r.unwrap();
                Command::none()
            }
        }
    }

    fn view(&self) -> iced::Element<'_, Self::Message, iced::Renderer<Self::Theme>> {
        let handle = iced::widget::svg::Handle::from_memory(
            include_bytes!("../../resources/logo.svg").to_vec(),
        );
        let logo = container(svg(handle)).padding(10);

        let tabs = column(
            vec![Tab::Summary, Tab::File, Tab::Network, Tab::Process]
                .into_iter()
                .map(|tab| {
                    button(text(format!("{:?}", tab)).font(Font {
                        weight: Weight::Bold,
                        ..Default::default()
                    }))
                    .on_press(Message::SwitchTab(tab))
                    .style(if matches!(self.state, State::OnTab(t) if t == tab) {
                        Button::Primary
                    } else {
                        Button::Secondary
                    })
                    .width(Length::Fill)
                    .into()
                })
                .collect(),
        )
        .spacing(10)
        .padding(10);
        let alerts = self
            .data
            .alerts
            .iter()
            .map(|alert| {
                container(text(&alert.message))
                    .style(match alert.severity {
                        0 => ContainerType::Red,
                        1 => ContainerType::Orange,
                        2 => ContainerType::Yellow,
                        3 => ContainerType::Card(5.0),
                        _ => ContainerType::Green,
                    })
                    .padding(5)
                    .width(Length::Fill)
                    .into()
            })
            .collect::<Vec<Element>>();
        let alerts = container(scrollable(column(alerts).spacing(5)))
            .padding(10.0)
            .style(ContainerType::SubtleCard(10.0))
            .width(Length::Fill);
        match &self.state {
            State::Processing => container(row!(
                Space::new(Length::FillPortion(3), 0),
                text("Processing, please wait. If you need to interact with the process, use the command line where Blackbox was started.").size(20).width(Length::FillPortion(3)),
                Space::new(Length::FillPortion(3), 0),
            )).height(Length::Fill).center_y().into(),
            State::OnTab(tab) => row!(
                container(column![logo, tabs])
                    .style(ContainerType::Card(0.0))
                    .height(Length::Fill)
                    .width(Length::FillPortion(1)),
                column!(
                    alerts,
                    match tab {
                        Tab::Summary => Self::summary_view(&self.data),
                        Tab::File => Self::file_view(&self.data),
                        Tab::Network => Self::network_view(&self.data),
                        Tab::Process => Self::process_view(&self.data),
                    }
                )
                .spacing(10.0)
                .width(Length::FillPortion(3))
                .padding(10),
            ).into()
        }
    }
}

type Element<'a> = iced::Element<
    'a,
    <App as iced::Application>::Message,
    iced::Renderer<<App as iced::Application>::Theme>,
>;

impl App {
    fn summary_view(data: &ProcessingData) -> Element<'_> {
        let file_summary = container(row![
            container(header("File access:")).width(150),
            Self::create_file_summary(&data.file_summary),
        ])
        .padding(10.0)
        .style(ContainerType::SubtleCard(10.0));

        let network_summary = container(row![
            container(header("Network:")).width(150),
            Self::create_network_summary(&data.network_summary)
        ])
        .padding(10.0)
        .style(ContainerType::SubtleCard(10.0));

        let process_summary = container(row![
            container(header("Processes:")).width(150),
            Self::create_process_summary(&data.process_summary)
        ])
        .width(Length::Fill)
        .padding(10.0)
        .style(ContainerType::SubtleCard(10.0));

        let main_view = column!(file_summary, network_summary, process_summary).spacing(10);
        scrollable(main_view)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn file_view(data: &ProcessingData) -> Element<'_> {
        let mut sorted_files = data.file_events.clone();
        sorted_files.sort_by(|a, b| a.start_time.cmp(&b.start_time));
        column![
            header("Summary:"),
            container(Self::create_file_summary(&data.file_summary))
                .padding(10.0)
                .style(ContainerType::SubtleCard(10.0)),
            header("File Access Details:"),
            scrollable(
                column(sorted_files.iter().map(Self::create_file_event).collect()).spacing(10.0)
            ),
        ]
        .into()
    }

    fn network_view(data: &ProcessingData) -> Element<'_> {
        column![
            header("Summary:"),
            container(Self::create_network_summary(&data.network_summary))
                .padding(10.0)
                .style(ContainerType::SubtleCard(10.0)),
            header("Connection Details:"),
            scrollable(
                column(
                    data.network_events
                        .iter()
                        .map(Self::create_connection)
                        .collect()
                )
                .spacing(10.0)
            ),
        ]
        .into()
    }

    fn process_view(data: &ProcessingData) -> Element<'_> {
        column![
            header("Summary:"),
            container(Self::create_process_summary(&data.process_summary))
                .width(Length::Fill)
                .padding(10.0)
                .style(ContainerType::SubtleCard(10.0)),
            header("Process Details:"),
            scrollable(
                column(
                    data.process_events
                        .iter()
                        .map(Self::create_spawn_event)
                        .collect()
                )
                .spacing(10.0)
            ),
        ]
        .into()
    }

    fn create_access_mark(access: AccessType) -> Element<'static> {
        let mut boxes = vec![];
        if access.read {
            boxes.push(("R", "read", ContainerType::Yellow));
        }
        if access.write {
            boxes.push(("W", "write", ContainerType::Orange));
        }
        if access.execute {
            boxes.push(("X", "execute", ContainerType::Red));
        }
        container(
            row(boxes
                .into_iter()
                .map(|(letter, word, style)| {
                    tooltip(
                        container(text(letter).font(Font {
                            weight: Weight::Bold,
                            family: Family::Monospace,
                            ..Default::default()
                        }))
                        .style(style)
                        .width(25)
                        .height(25)
                        .center_x()
                        .center_y(),
                        word,
                        tooltip::Position::FollowCursor,
                    )
                    .style(ContainerType::SubtleCard(5.0))
                    .into()
                })
                .collect())
            .spacing(3),
        )
        .into()
    }

    fn create_file_summary(file_summary: &FileSummary) -> Element<'static> {
        column![
            row![
                container(
                    column![
                        row![
                            tooltip(text("Standard I/O:"), "The normal console input and output of the program.", tooltip::Position::FollowCursor).style(ContainerType::SubtleCard(5.0)),
                            Space::with_width(Length::Fill),
                            Self::create_access_mark(file_summary.behavior.stdio),
                        ],
                        row![
                            tooltip(text("Current Directory:"), "The directory that the process was executed in.", tooltip::Position::FollowCursor).style(ContainerType::SubtleCard(5.0)),
                            Space::with_width(Length::Fill),
                            Self::create_access_mark(file_summary.behavior.current_dir),
                        ],
                        row![
                            tooltip(text("Home Directory:"), "The user's home directory, and any folders inside it.", tooltip::Position::FollowCursor).style(ContainerType::SubtleCard(5.0)),
                            Space::with_width(Length::Fill),
                            Self::create_access_mark(file_summary.behavior.home_dir),
                        ],
                        row![
                            tooltip(text("System Files:"), "System files, such as installation directories and root directories. Processes should normally only execute files from here.", tooltip::Position::FollowCursor).style(ContainerType::SubtleCard(5.0)),
                            Space::with_width(Length::Fill),
                            Self::create_access_mark(file_summary.behavior.system),
                        ],
                        row![
                            tooltip(text("Runtime Directories:"), "Special directories such as /tmp and /proc that are managed by the system when it is running.", tooltip::Position::FollowCursor).style(ContainerType::SubtleCard(5.0)),
                            Space::with_width(Length::Fill),
                            Self::create_access_mark(file_summary.behavior.runtime),
                        ],
                    ]
                    .spacing(3)
                )
                .width(Length::FillPortion(1)),
                container(column![
                    text(format!("Files Accessed: {}", file_summary.access_count)),
                    text(format!("Total Bytes Read: {}", file_summary.bytes_read)),
                    text(format!(
                        "Total Bytes Written: {}",
                        file_summary.bytes_written
                    )),
                ])
                .width(Length::FillPortion(1))
            ]
            .spacing(10),
            row![
                text("Directories accessed:"),
                scrollable(
                    column(
                        file_summary
                            .directories
                            .iter()
                            .map(|dir| monospace(dir.to_string_lossy()))
                            .collect()
                    )
                    .spacing(3)
                )
                .height(100)
                .width(Length::Fill)
            ]
            .spacing(10.0),
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
                    scrollable(
                        column(
                            network_summary
                                .domains
                                .iter()
                                .map(|domain| chip(domain.text(), domain.tooltip()))
                                .collect()
                        )
                        .spacing(3)
                    )
                ]
                .width(Length::FillPortion(1)),
                column![
                    text("Protocols:"),
                    scrollable(
                        column(
                            network_summary
                                .protocols
                                .iter()
                                .map(|protocol| chip(protocol.text(), protocol.tooltip()))
                                .collect()
                        )
                        .spacing(3)
                    )
                ]
                .width(Length::FillPortion(1))
            ],
        ]
        .into()
    }

    fn create_process_summary(process_summary: &ProcessSummary) -> Element<'static> {
        if process_summary.processes_created == 0 {
            text("No other processes created").into()
        } else {
            column![
                text(format!(
                    "Total Processes Spawned: {}",
                    process_summary.processes_created,
                )),
                row![
                    text("Most Common Spawn Type:"),
                    chip(
                        process_summary.most_common_spawn_type.text(),
                        process_summary.most_common_spawn_type.tooltip()
                    )
                ]
                .spacing(5),
                row![
                    text("Processes executed:"),
                    scrollable(
                        column(
                            process_summary
                                .programs
                                .iter()
                                .map(|program| monospace(program.to_string_lossy()))
                                .collect()
                        )
                        .spacing(5)
                    ),
                ]
                .spacing(10)
            ]
            .spacing(3)
            .into()
        }
    }

    fn create_file_event(access: &FileAccess) -> Element<'static> {
        let data_views: Element = if access.read_data.is_empty() && access.write_data.is_empty() {
            container(text("No file data recorded.")).into()
        } else {
            let mut row = Row::new();
            if !access.read_data.is_empty() {
                row = row.push(column!(
                    text("Read data:"),
                    Self::create_hex_preview(&access.read_data)
                ));
            }
            if !access.write_data.is_empty() {
                row = row.push(column!(
                    text("Write data:"),
                    Self::create_hex_preview(&access.write_data)
                ));
            }
            row.width(Length::Fill).into()
        };
        let name = if access.file_descriptor < 3 {
            text(match access.file_descriptor {
                0 => "Standard In",
                1 => "Standard Out",
                2 => "Standard Error",
                _ => unreachable!(),
            })
        } else if let Some(name) = &access.file_name {
            text(name.to_string_lossy()).font(Font::MONOSPACE)
        } else {
            text("No file name recorded")
        };
        container(
            column![
                row![
                    chip(
                        access.file_descriptor,
                        "The Unix file descriptor for this file"
                    ),
                    name.size(20),
                    Self::create_access_mark(access.access_type),
                ]
                .align_items(iced::Alignment::Center)
                .spacing(10),
                text(format!("Total Data Length: {}", access.data_length)),
                text(format!(
                    "Duration: {}",
                    duration(access.start_time, access.end_time)
                )),
                data_views,
            ]
            .spacing(5),
        )
        .width(Length::Fill)
        .style(ContainerType::SubtleCard(5.0))
        .padding(5.0)
        .into()
    }

    fn create_hex_preview(bytes: &[u8]) -> Element<'static> {
        let hex = column(
            bytes
                .chunks(16)
                .map(|chunk| {
                    row(chunk
                        .iter()
                        .map(|b| text(format!("{:02x}", b)).font(Font::MONOSPACE).into())
                        .collect())
                    .spacing(3)
                    .into()
                })
                .collect(),
        )
        .spacing(3);
        let string = column(
            bytes
                .chunks(16)
                .map(|chunk| {
                    text(
                        chunk
                            .iter()
                            .map(|b| {
                                let c = char::from_u32(*b as u32).unwrap_or('\0');
                                if c.is_ascii_digit()
                                    || c.is_alphabetic()
                                    || (c.is_ascii()
                                        && !(c.is_ascii_control() || c.is_ascii_whitespace()))
                                {
                                    c
                                } else {
                                    '.'
                                }
                            })
                            .collect::<String>(),
                    )
                    .font(Font::MONOSPACE)
                    .into()
                })
                .collect(),
        )
        .spacing(3);
        row!(hex, string).spacing(10).into()
    }

    fn create_connection(conn: &Connection) -> Element<'static> {
        container(
            column![
                text(format!(
                    "Duration: {}",
                    duration(conn.start_time, conn.end_time)
                )),
                row![
                    text("Protocol:"),
                    chip(conn.protocol.text(), conn.protocol.tooltip())
                ]
                .spacing(5),
                row![
                    text("Domain:"),
                    chip(conn.domain.text(), conn.domain.tooltip())
                ]
                .spacing(5),
            ]
            .spacing(3),
        )
        .style(ContainerType::SubtleCard(5.0))
        .width(Length::Fill)
        .padding(5.0)
        .into()
    }

    fn create_spawn_event(spawn: &SpawnEvent) -> Element<'static> {
        container(column![
            row![
                match &spawn.command {
                    Some(os_str) => {
                        text(os_str.to_string_lossy())
                            .font(Font::MONOSPACE)
                            .size(20)
                    }
                    None => {
                        text("No Command").size(20)
                    }
                },
                row![
                    chip(spawn.parent_id, "The parent Process ID (PID)"),
                    text("-"),
                    chip(spawn.process_id, "The child Process ID (PID)")
                ]
                .align_items(iced::Alignment::Center)
                .spacing(3)
            ]
            .align_items(iced::Alignment::Center)
            .spacing(10),
            text(format!("Timestamp: {}", spawn.spawn_time)),
            row![
                text("Spawn Type:"),
                chip(spawn.spawn_type.text(), spawn.spawn_type.tooltip())
            ]
            .spacing(5),
        ])
        .style(ContainerType::SubtleCard(5.0))
        .width(Length::Fill)
        .padding(5.0)
        .into()
    }
}

fn monospace(t: impl ToString) -> Element<'static> {
    container(text(t).font(Font::MONOSPACE))
        .style(ContainerType::Card(3.0))
        .padding([3, 5, 2, 5])
        .into()
}

fn chip(t: impl ToString, tip: impl ToString) -> Element<'static> {
    tooltip(
        container(text(t).size(12).font(Font {
            weight: Weight::Bold,
            ..Default::default()
        }))
        .style(ContainerType::Card(25.0))
        .padding([3, 7, 2, 7]),
        tip,
        tooltip::Position::FollowCursor,
    )
    .style(ContainerType::SubtleCard(5.0))
    .into()
}

fn header(t: impl ToString) -> Element<'static> {
    container(
        text(t)
            .size(18)
            .font(Font {
                weight: Weight::Bold,
                ..Default::default()
            })
            .style(OFF_BLACK),
    )
    .padding([10, 0, 5, 0])
    .into()
}

fn duration(start: u64, end: u64) -> String {
    let time = end as i64 - start as i64;
    if time < 0 || start == 0 {
        return String::from("??");
    }
    match time {
        t if t > 1e9 as i64 => {
            format!("{:.1}s", (t as f64) / 1e9)
        }
        t if t > 1e6 as i64 => {
            format!("{:.1}ms", (t as f64) / 1e6)
        }
        t if t > 1e3 as i64 => {
            format!("{:.1}µs", (t as f64) / 1e3)
        }
        t => {
            format!("{:.1}ns", (t as f64))
        }
    }
}
