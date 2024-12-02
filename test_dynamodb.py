import json
from FitOn.models import Exercise, MuscleGroup

# Load the JSON data from exercise.json
with open('exercise-list.json', 'r') as file:
    exercises_data = json.load(file)

# Loop through each exercise in the data
for exercise_data in exercises_data["exercises"]:
    # Create or get the Exercise instance
    exercise, created = Exercise.objects.get_or_create(
        name=exercise_data["name"],
        defaults={
            "force": exercise_data.get("force"),
            "level": exercise_data.get("level"),
            "mechanic": exercise_data.get("mechanic"),
            "equipment": exercise_data.get("equipment"),
            "instructions": " ".join(exercise_data.get("instructions", [])),
            "category": exercise_data.get("category"),
        }
    )
    
    # Add primary muscles
    for muscle_name in exercise_data.get("primaryMuscles", []):
        muscle, _ = MuscleGroup.objects.get_or_create(name=muscle_name)
        exercise.primaryMuscles.add(muscle)
    
    # Add secondary muscles
    for muscle_name in exercise_data.get("secondaryMuscles", []):
        muscle, _ = MuscleGroup.objects.get_or_create(name=muscle_name)
        exercise.secondaryMuscles.add(muscle)
    
    # Save the exercise
    exercise.save()

    if created:
        print(f"Added new exercise: {exercise.name}")
    else:
        print(f"Updated existing exercise: {exercise.name}")
