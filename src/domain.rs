use clap::ValueEnum;
use regex::Regex;
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Hash)]
pub enum ToolKind {
    Go,
    Rust,
    Node,
    Python,
    Flutter,
}

impl ToolKind {
    pub fn all() -> Vec<ToolKind> {
        vec![
            ToolKind::Go,
            ToolKind::Rust,
            ToolKind::Node,
            ToolKind::Python,
            ToolKind::Flutter,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ToolKind::Go => "go",
            ToolKind::Rust => "rust",
            ToolKind::Node => "node",
            ToolKind::Python => "python",
            ToolKind::Flutter => "flutter",
        }
    }
}

#[derive(Clone, Debug)]
pub enum UpdateMethod {
    BuiltIn,
    DirectDownload,
}

#[derive(Clone, Debug)]
pub struct ToolReport {
    pub tool: ToolKind,
    pub installed: Option<Version>,
    pub latest: Option<Version>,
    pub status: Status,
    pub method: UpdateMethod,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    UpToDate,
    Outdated,
    NotInstalled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>, // keep simple
}

impl Version {
    pub fn parse_loose(s: &str) -> Option<Self> {
        // Accept: "1.2.3", "v1.2.3", "go1.22.5", "rustc 1.85.0", "3.22.1-foo"
        let re =
            Regex::new(r"(?i)(?:go|v|rustc\s+)?(\d+)\.(\d+)\.(\d+)(?:[-+~._]([0-9A-Za-z.-]+))?")
                .ok()?;
        let caps = re.captures(s)?;
        let major = caps.get(1)?.as_str().parse().ok()?;
        let minor = caps.get(2)?.as_str().parse().ok()?;
        let patch = caps.get(3)?.as_str().parse().ok()?;
        let pre = caps.get(4).map(|m| m.as_str().to_string());
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    pub fn to_string(&self) -> String {
        match &self.pre {
            Some(p) => format!("{}.{}.{}-{}", self.major, self.minor, self.patch, p),
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch, &self.pre).cmp(&(
            other.major,
            other.minor,
            other.patch,
            &other.pre,
        ))
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
