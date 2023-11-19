use iced::{
    theme::{Button, Scrollable, Text},
    Background, Color,
};

#[derive(Debug, Default)]
pub struct Theme {}

impl iced::application::StyleSheet for Theme {
    type Style = ();

    fn appearance(&self, _: &Self::Style) -> iced::application::Appearance {
        iced::application::Appearance {
            text_color: BLACK,
            background_color: WHITE,
        }
    }
}

impl iced::widget::button::StyleSheet for Theme {
    type Style = Button;

    fn active(&self, style: &Self::Style) -> iced::widget::button::Appearance {
        match style {
            Button::Primary => iced::widget::button::Appearance {
                text_color: WHITE,
                background: Some(Background::Color(ACCENT)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            Button::Secondary => iced::widget::button::Appearance {
                text_color: BLACK,
                background: Some(Background::Color(OFF_WHITE)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            Button::Positive => iced::widget::button::Appearance {
                text_color: BLACK,
                background: Some(Background::Color(ACCENT_ALT)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            Button::Destructive => iced::widget::button::Appearance {
                text_color: BLACK,
                background: Some(Background::Color(RED)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            Button::Text => iced::widget::button::Appearance {
                text_color: ACCENT,
                background: None,
                ..Default::default()
            },
            Button::Custom(_) => unimplemented!(),
        }
    }
}

impl iced::widget::text::StyleSheet for Theme {
    type Style = Text;

    fn appearance(&self, style: Self::Style) -> iced::widget::text::Appearance {
        match style {
            Text::Default => iced::widget::text::Appearance { color: None },
            Text::Color(color) => iced::widget::text::Appearance { color: Some(color) },
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum ContainerType {
    #[default]
    Transparent,
    Red,
    Orange,
    Yellow,
    Green,
    Card,
}

impl iced::widget::container::StyleSheet for Theme {
    type Style = ContainerType;

    fn appearance(&self, style: &Self::Style) -> iced::widget::container::Appearance {
        match style {
            ContainerType::Transparent => iced::widget::container::Appearance {
                text_color: Some(BLACK),
                ..Default::default()
            },
            ContainerType::Red => iced::widget::container::Appearance {
                text_color: Some(BLACK),
                background: Some(Background::Color(RED)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            ContainerType::Orange => iced::widget::container::Appearance {
                text_color: Some(BLACK),
                background: Some(Background::Color(ORANGE)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            ContainerType::Yellow => iced::widget::container::Appearance {
                text_color: Some(BLACK),
                background: Some(Background::Color(YELLOW)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            ContainerType::Green => iced::widget::container::Appearance {
                text_color: Some(BLACK),
                background: Some(Background::Color(ACCENT_ALT)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
            ContainerType::Card => iced::widget::container::Appearance {
                text_color: Some(BLACK),
                background: Some(Background::Color(OFF_WHITE)),
                border_radius: 5.0.into(),
                ..Default::default()
            },
        }
    }
}

impl iced::widget::scrollable::StyleSheet for Theme {
    type Style = Scrollable;

    fn active(&self, style: &Self::Style) -> iced::widget::scrollable::Scrollbar {
        match style {
            Scrollable::Default => iced::widget::scrollable::Scrollbar {
                background: None,
                border_radius: 0.0.into(),
                border_width: 0.0,
                border_color: WHITE,
                scroller: iced::widget::scrollable::Scroller {
                    color: OFF_WHITE,
                    border_radius: 3.0.into(),
                    border_width: 0.0,
                    border_color: WHITE,
                },
            },
            Scrollable::Custom(_) => unimplemented!(),
        }
    }

    fn hovered(
        &self,
        style: &Self::Style,
        is_mouse_over_scrollbar: bool,
    ) -> iced::widget::scrollable::Scrollbar {
        match style {
            Scrollable::Default => iced::widget::scrollable::Scrollbar {
                background: None,
                border_radius: 0.0.into(),
                border_width: 0.0,
                border_color: WHITE,
                scroller: iced::widget::scrollable::Scroller {
                    color: if is_mouse_over_scrollbar {
                        ACCENT
                    } else {
                        OFF_WHITE
                    },
                    border_radius: 3.0.into(),
                    border_width: 0.0,
                    border_color: WHITE,
                },
            },
            Scrollable::Custom(_) => unimplemented!(),
        }
    }
}

pub const WHITE: Color = Color {
    r: 247.0 / 255.0,
    g: 247.0 / 255.0,
    b: 247.0 / 255.0,
    a: 1.0,
};
pub const OFF_WHITE: Color = Color {
    r: 230.0 / 255.0,
    g: 230.0 / 255.0,
    b: 230.0 / 255.0,
    a: 1.0,
};
pub const BLACK: Color = Color {
    r: 10.0 / 255.0,
    g: 23.0 / 255.0,
    b: 5.0 / 255.0,
    a: 1.0,
};
pub const OFF_BLACK: Color = Color {
    r: 14.0 / 255.0,
    g: 34.0 / 255.0,
    b: 5.0 / 255.0,
    a: 1.0,
};
pub const ACCENT: Color = Color {
    r: 20.0 / 255.0,
    g: 49.0 / 255.0,
    b: 9.0 / 255.0,
    a: 1.0,
};
pub const ACCENT_ALT: Color = Color {
    r: 114.0 / 255.0,
    g: 132.0 / 255.0,
    b: 94.0 / 255.0,
    a: 1.0,
};
pub const RED: Color = Color {
    r: 195.0 / 255.0,
    g: 84.0 / 255.0,
    b: 84.0 / 255.0,
    a: 1.0,
};
pub const ORANGE: Color = Color {
    r: 219.0 / 255.0,
    g: 138.0 / 255.0,
    b: 80.0 / 255.0,
    a: 1.0,
};
pub const YELLOW: Color = Color {
    r: 241.0 / 255.0,
    g: 218.0 / 255.0,
    b: 116.0 / 255.0,
    a: 1.0,
};
