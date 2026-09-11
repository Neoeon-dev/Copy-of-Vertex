-- MailTrace Seed Data
-- This file provides initial data for development/testing

-- Create a default case for testing
INSERT INTO cases (title, description) VALUES
    ('Demo Investigation', 'Automatically created for development and testing purposes')
ON CONFLICT DO NOTHING;
