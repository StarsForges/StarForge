use crate::utils::{
    print as p,
    security_training::{self, Lesson},
};
use anyhow::Result;
use clap::Subcommand;
use colored::*;

#[derive(Subcommand)]
pub enum SecurityTrainingCommands {
    /// List available security training topics
    List,
    /// Start or resume a topic by slug (e.g. secure-coding)
    Start { topic: String },
    /// Answer the current quiz question (1-based option number)
    Answer { choice: usize },
    /// Show training progress across all topics
    Status,
    /// Get a personalized recommendation for what to study next
    Recommend,
}

pub fn handle(cmd: SecurityTrainingCommands) -> Result<()> {
    match cmd {
        SecurityTrainingCommands::List => list(),
        SecurityTrainingCommands::Start { topic } => start(&topic),
        SecurityTrainingCommands::Answer { choice } => answer(choice),
        SecurityTrainingCommands::Status => status(),
        SecurityTrainingCommands::Recommend => recommend(),
    }
}

fn list() -> Result<()> {
    let training_status = security_training::load_status()?;
    p::header("Security Training Topics");
    p::separator();

    for lesson in security_training::all_lessons() {
        let progress = training_status.progress.get(&lesson.topic);
        let marker = match progress {
            Some(p) if p.completed => "✓".green().to_string(),
            Some(p) if p.attempts > 0 => "…".yellow().to_string(),
            _ => "•".dimmed().to_string(),
        };
        println!(
            "  {} {} — {}",
            marker,
            lesson.topic.cyan().bold(),
            lesson.summary.dimmed()
        );
    }
    p::separator();
    p::info(&format!(
        "Overall progress: {:.0}%",
        security_training::overall_completion_percent(&training_status)
    ));
    p::info("Start with: starforge ai security-training start secure-coding");
    p::info("Not sure where to start? starforge ai security-training recommend");
    Ok(())
}

fn start(topic: &str) -> Result<()> {
    let lesson = security_training::find_lesson(topic).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown topic '{}'. Available topics: {}",
            topic,
            security_training::topic_slugs().join(", ")
        )
    })?;

    let mut training_status = security_training::load_status()?;
    training_status.active_topic = Some(lesson.topic.clone());
    training_status.current_question = 0;
    security_training::save_status(&training_status)?;

    p::header(&lesson.title);
    println!("  {}\n", lesson.summary.dimmed());
    for point in &lesson.content {
        println!("  • {}", point.white());
    }
    p::separator();
    print_question(&lesson, 0);
    p::info("Answer with: starforge ai security-training answer <option-number>");
    Ok(())
}

fn answer(choice: usize) -> Result<()> {
    let mut training_status = security_training::load_status()?;
    let topic = training_status.active_topic.clone().ok_or_else(|| {
        anyhow::anyhow!("No active topic. Run starforge ai security-training start <topic>")
    })?;
    let lesson = security_training::find_lesson(&topic)
        .ok_or_else(|| anyhow::anyhow!("Active topic '{}' no longer exists", topic))?;

    let q_index = training_status.current_question;
    let question = lesson.questions.get(q_index).ok_or_else(|| {
        anyhow::anyhow!(
            "No active question. Run starforge ai security-training start {}",
            topic
        )
    })?;

    if choice == 0 || choice > question.options.len() {
        anyhow::bail!(
            "Invalid option {}. Choose a number between 1 and {}.",
            choice,
            question.options.len()
        );
    }

    let correct = choice - 1 == question.correct_index;

    let entry = training_status.progress.entry(topic.clone()).or_default();
    entry.attempts += 1;
    if correct {
        entry.correct += 1;
    }
    entry.last_studied_at = Some(chrono::Utc::now().to_rfc3339());

    if correct {
        p::success("Correct!");
    } else {
        p::warn(&format!(
            "Not quite. Correct answer: {}",
            question.options[question.correct_index]
        ));
    }
    println!("  {}", question.explanation.dimmed());

    let next_index = q_index + 1;
    if next_index >= lesson.questions.len() {
        training_status
            .progress
            .entry(topic.clone())
            .or_default()
            .completed = true;
        training_status.active_topic = None;
        training_status.current_question = 0;
        security_training::save_status(&training_status)?;

        println!();
        p::success(&format!("Topic '{}' complete!", topic));
        if let Some(next_topic) = security_training::recommend_topic(&training_status) {
            p::info(&format!(
                "Recommended next: starforge ai security-training start {}",
                next_topic
            ));
        } else {
            p::info("You've completed every available topic. Nice work.");
        }
    } else {
        training_status.current_question = next_index;
        security_training::save_status(&training_status)?;
        println!();
        print_question(&lesson, next_index);
    }

    Ok(())
}

fn status() -> Result<()> {
    let training_status = security_training::load_status()?;
    p::header("Security Training Status");
    p::separator();

    if training_status.progress.is_empty() {
        p::info("No topics started yet.");
    } else {
        println!(
            "  {:<24}  {:<10}  {:<10}  {}",
            "Topic".dimmed(),
            "Attempts".dimmed(),
            "Accuracy".dimmed(),
            "Status".dimmed(),
        );
        for lesson in security_training::all_lessons() {
            let Some(p) = training_status.progress.get(&lesson.topic) else {
                continue;
            };
            let state = if p.completed {
                "✓ completed".green().to_string()
            } else {
                "in progress".yellow().to_string()
            };
            println!(
                "  {:<24}  {:<10}  {:<10}  {}",
                lesson.topic.cyan(),
                p.attempts,
                format!("{:.0}%", p.accuracy()),
                state,
            );
        }
    }

    p::separator();
    p::kv_accent(
        "Overall Progress",
        &format!(
            "{:.0}%",
            security_training::overall_completion_percent(&training_status)
        ),
    );
    if let Some(active) = &training_status.active_topic {
        p::kv("Active Topic", active);
        p::kv(
            "Current Question",
            &format!("{}", training_status.current_question + 1),
        );
    }
    Ok(())
}

fn recommend() -> Result<()> {
    let training_status = security_training::load_status()?;
    match security_training::recommend_topic(&training_status) {
        Some(topic) => {
            let lesson = security_training::find_lesson(&topic);
            p::header("Recommended Topic");
            p::kv_accent("Topic", &topic);
            if let Some(l) = lesson {
                p::kv("Why", &l.summary);
            }
            p::info(&format!(
                "Start with: starforge ai security-training start {}",
                topic
            ));
        }
        None => {
            p::success("You've completed every available security training topic!");
        }
    }
    Ok(())
}

fn print_question(lesson: &Lesson, index: usize) {
    let Some(question) = lesson.questions.get(index) else {
        return;
    };
    println!(
        "  {} ({}/{})",
        "Question".bright_white().bold(),
        index + 1,
        lesson.questions.len()
    );
    println!("  {}\n", question.prompt.white());
    for (i, option) in question.options.iter().enumerate() {
        println!("    {}. {}", i + 1, option);
    }
}
